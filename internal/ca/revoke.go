// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// Revoke serialises on the cluster-wide "crl" lock so concurrent revocations
// (and any future CRL rotation) on different replicas cannot both read the
// same CRL, each append their own entry, and clobber one another's write.
func (c *CA) Revoke(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.revokeLocked(ctx, subject)
	})
}

// revokeLocked performs the actual CRL read-modify-write. The cluster CRL
// lock and c.mu must both be held by the caller.
func (c *CA) revokeLocked(ctx context.Context, subject string) error {
	slog.Debug("Revoking certificate", "subject", subject)

	serialStr, err := c.findSerialForSubject(ctx, subject)
	if err != nil {
		// A read failure is counted; a subject that was simply never issued is
		// not. The metric's documented meaning is "a revocation that could not be
		// recorded", and an inventory read that fails is one. On a blob backend
		// that includes an HMAC verification failure -- a tamper signal -- since
		// the read goes through ReadInventory; the SQL backends answer from an
		// indexed SELECT, which verifies nothing, so there the counted cases are
		// connection and query failures. An *absent* inventory on a blob backend
		// reaches fs.ErrNotExist and is classed as never-issued, so it is not
		// counted either. It matters
		// because Clean swallows this error and deletes anyway, so without the
		// increment a clean silently became delete-without-revoke with one WARN
		// line and a flat counter, leaving the alert the mixin ships unable to
		// fire. Not-found is excluded deliberately: a typo'd certname would
		// otherwise page someone.
		// Both the blob and the SQL inventory report a missing subject by
		// wrapping fs.ErrNotExist, so one check covers every backend.
		if !errors.Is(err, fs.ErrNotExist) {
			c.crlUpdateFailures.Add(1)
		}
		return fmt.Errorf("could not find certificate for subject %s: %w", subject, err)
	}

	if err := c.revokeSerialLocked(ctx, serialStr); err != nil {
		// Name the serial. Clean logs this error and deletes the certificate
		// anyway, so this is often the last place the serial of a certificate
		// that is still a valid credential is recorded — and it is what
		// RevokeSerial needs to retire it once the cause is fixed.
		return fmt.Errorf("revoking serial %s for subject %s: %w", serialStr, subject, err)
	}

	slog.Debug("Certificate revoked", "subject", subject, "serial", serialStr)
	return nil
}

// ErrSerialUnknown is returned by RevokeSerial for a serial no inventory entry
// carries. It is deliberately not overridable by force: a serial this CA has no
// record of issuing cannot be cleaned out of the CRL again, because
// CleanupExpiredCerts drops CRL entries only for serials it finds in the
// inventory. Admitting one would grow the CRL — served to every agent — by an
// entry with no expiry, forever.
var ErrSerialUnknown = errors.New("serial number not found in inventory")

// ErrSerialIsCurrent is returned by RevokeSerial when the serial is the one on
// the certificate currently stored for its subject — the live credential. That
// is the case revoke --certname already covers, so reaching it by serial is far
// more likely a mistyped digit than an intent, and the consequence (a working
// node loses its certificate) is the expensive direction to be wrong in.
var ErrSerialIsCurrent = errors.New("serial belongs to the certificate currently in use")

// RevokeSerial revokes one specific serial number, rather than whatever serial
// is currently newest for a subject.
//
// Revocation is otherwise only ever by subject: Revoke resolves through
// findSerialForSubject, which answers with the *latest* serial issued for that
// name. That leaves a superseded certificate unreachable once a replacement has
// been issued — the state a failed supersession record leaves behind — since
// asking to revoke the subject now takes the working certificate out of
// circulation and leaves the superseded one valid.
//
// force overrides the ErrSerialIsCurrent guard only. It is the escape hatch for
// deliberately retiring a live certificate by serial (a compromise where the
// operator has the serial in hand and not the name); it does not admit a serial
// this CA never issued.
//
// Locking matches Revoke: the cluster-wide "crl" lock, then c.mu, so concurrent
// revocations on different replicas cannot clobber one another's CRL write.
func (c *CA) RevokeSerial(ctx context.Context, serial string, force bool) error {
	normalised, err := storage.NormaliseSerial(serial)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.revokeSerialCheckedLocked(ctx, normalised, force)
	})
}

// revokeSerialCheckedLocked is RevokeSerial's body: resolve the serial to a
// subject, refuse the live certificate unless forced, then revoke. serial must
// already be normalised. The cluster CRL lock and c.mu must both be held.
func (c *CA) revokeSerialCheckedLocked(ctx context.Context, serial string, force bool) error {
	subject, err := c.Storage.SubjectForSerial(ctx, serial)
	if err != nil {
		// Same split as revokeLocked: a serial that was simply never issued is
		// operator error and is not counted, but an inventory read that *failed*
		// is a revocation that could not be recorded, which is what
		// crlUpdateFailures means. On a blob backend that includes an HMAC
		// verification failure — a tamper signal — since the read goes through
		// ReadInventory.
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrSerialUnknown, serial)
		}
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("looking up serial %s in inventory: %w", serial, err)
	}

	live, err := c.storedCertSerial(ctx, subject)
	switch {
	case err != nil:
		// Fail closed. The question this answers is "would revoking this serial
		// take a working credential out of circulation", and an unreadable
		// certificate is precisely the case where we cannot say it would not.
		// Deleted material reaches fs.ErrNotExist and is handled below; anything
		// else is an I/O or parse failure, and treating that as "not live" would
		// let the guard evaporate exactly when storage is unhealthy.
		if !errors.Is(err, fs.ErrNotExist) {
			if !force {
				return fmt.Errorf("cannot confirm whether serial %s is the certificate currently stored for %s: %w",
					serial, subject, err)
			}
			slog.Warn("Revoking by serial without confirming the stored certificate",
				"serial", serial, "subject", subject, "error", err)
		}
	case live == serial && !force:
		return fmt.Errorf("%w: %s is the certificate stored for %s; "+
			"revoke it by name with --certname %s, or pass --force to revoke it by serial anyway",
			ErrSerialIsCurrent, serial, subject, subject)
	case live == serial:
		slog.Warn("Revoking the certificate currently stored for a subject, by serial and forced",
			"serial", serial, "subject", subject)
	}

	slog.Debug("Revoking certificate by serial", "serial", serial, "subject", subject, "force", force)
	if err := c.revokeSerialLocked(ctx, serial); err != nil {
		return err
	}
	slog.Info("Certificate revoked by serial", "serial", serial, "subject", subject)
	return nil
}

// storedCertSerial returns the normalised serial of the certificate currently
// stored for subject, wrapping fs.ErrNotExist when no certificate is stored.
//
// It reads the stored certificate rather than asking LatestSerialForSubject
// because the two answer different questions. The inventory's newest row for a
// subject is the newest *issuance*; the stored certificate is the credential in
// circulation. They diverge after a clean (the inventory rows outlive the
// deleted blob) and while an issuance is only partly complete, and it is the
// second that this guard is about.
func (c *CA) storedCertSerial(ctx context.Context, subject string) (string, error) {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("stored certificate for %s is not valid PEM", subject)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing stored certificate for %s: %w", subject, err)
	}
	return serialHexStr(cert.SerialNumber), nil
}

// revokeSerialLocked adds serialStr to the CRL, unless it is already present.
// The cluster CRL lock and c.mu must both be held by the caller.
//
// This is split out from revokeLocked so Renew and AutoRenew can revoke the
// exact serial of the certificate they are replacing. By the time either
// wants to revoke, issueLeafLocked has already appended the new cert's row
// to the inventory, so findSerialForSubject (latest-issued-for-subject) would
// resolve to the new serial rather than the one being retired.
func (c *CA) revokeSerialLocked(ctx context.Context, serialStr string) error {
	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(serialStr, 16); !ok {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("malformed serial %q", serialStr)
	}

	// 1. Load CRL. readStoredCRL counts its own failures now, so this path must
	// not add a second increment for the same event.
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}

	// 2. Check for duplicate revocation: a serial that's already in the CRL
	// should not be appended again (prevents unbounded CRL growth on retries).
	for _, entry := range stored.own.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serialInt) == 0 {
			slog.Debug("Certificate already revoked", "serial", serialStr)
			// Still project the state into the certificate index: a retried
			// revocation may be exactly the case where the CRL write landed
			// but the index update did not.
			c.markCertRevokedIndex(ctx, serialStr, entry.RevocationTime)
			return nil
		}
	}

	// 3. Append the new entry and re-sign. signCRLLocked counts its own
	// sign/write failures into crlUpdateFailures, so this path does not
	// double-count them.
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serialInt,
		RevocationTime: time.Now(),
	}

	revokedCerts := stored.own.RevokedCertificateEntries
	revokedCerts = append(revokedCerts, newRevoked)

	if err := c.signCRLLocked(ctx, stored, revokedCerts); err != nil {
		return err
	}

	// Project the revocation into the certificate index. The signed CRL just
	// written is the source of truth; the index column is a display cache of
	// it, so a failure here is logged, not propagated — the revocation has
	// already happened, and the startup index repair reconverges the column.
	c.markCertRevokedIndex(ctx, serialStr, newRevoked.RevocationTime)

	// Invalidate the cached OCSP response for this serial so the next query
	// returns the correct Revoked status instead of a stale Good response.
	// Use the same normalised key as the OCSP index (uppercase hex, no padding).
	delete(c.ocspCache, serialHexStr(serialInt))

	return nil
}

// markCertRevokedIndex is the log-and-continue wrapper around
// StorageService.MarkCertRevoked used by the revocation paths.
func (c *CA) markCertRevokedIndex(ctx context.Context, serialStr string, at time.Time) {
	if err := c.Storage.MarkCertRevoked(ctx, serialStr, at); err != nil {
		slog.Warn("Failed to project revocation into certificate index",
			"serial", serialStr, "error", err)
	}
}

// parseInventoryLine parses a single line of the certificate inventory file.
// The format is: SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
// Returns (serial, subject, true) on success; ("", "", false) for blank or malformed lines.
// The returned subject has its leading "/" stripped.
func parseInventoryLine(line string) (serial, subject string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return "", "", false
	}
	return parts[0], strings.TrimPrefix(parts[3], "/"), true
}

// findSerialForSubject returns the most-recently issued serial for subject.
// It delegates to storage, which uses an indexed lookup on structured backends
// and a verified blob scan otherwise.
func (c *CA) findSerialForSubject(ctx context.Context, subject string) (string, error) {
	return c.Storage.LatestSerialForSubject(ctx, subject)
}

// IsRevokedSerial reports whether the given serial number appears in the
// current CRL.  Unlike IsRevoked, this checks the serial of the certificate
// directly rather than looking up whatever cert happens to be on disk for a
// given CN.  The caller should pass cert.SerialNumber from the certificate
// that is actually being evaluated (e.g. the TLS-presented peer certificate).
//
// Returns (false, err) when the CRL cannot be read or parsed; callers that use
// this result for an authentication decision should treat an error as a denial
// (fail-closed).
func (c *CA) IsRevokedSerial(ctx context.Context, serial *big.Int) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedCRL == nil {
		return false, fmt.Errorf("CRL not loaded")
	}
	for _, entry := range c.cachedCRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// IsRevoked checks whether the certificate for subject appears in the CRL.
// It looks up the cert currently on disk for subject and checks that cert's
// serial; it is suitable for display purposes (e.g. certificate status
// responses) but NOT for authentication decisions.  For auth, use
// IsRevokedSerial with the serial of the presented certificate instead.
// Returns false (not an error) if the subject has no signed cert.
func (c *CA) IsRevoked(ctx context.Context, subject string) bool {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	c.mu.RLock()
	crl := c.cachedCRL
	c.mu.RUnlock()

	if crl == nil {
		slog.Warn("IsRevoked: CRL not loaded, assuming not revoked (fail-open for display only)", "subject", subject)
		return false
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
