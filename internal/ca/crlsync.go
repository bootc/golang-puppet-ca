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
	"fmt"
	"log/slog"
	"math/big"
)

// SyncCRLCache reloads the in-memory CRL from storage when the stored one has
// moved ahead of the cached copy, and reports whether it replaced it.
//
// This is what makes a revocation take effect on the replicas that did not
// perform it. Every admission decision the CA makes about a presented
// certificate — IsRevokedSerial on the mTLS path, the OCSP responder, the
// re-issuance eviction check — answers from c.cachedCRL, which is otherwise
// only written when *this* process re-signs the CRL or starts up. On a shared
// backend that leaves a peer admitting a certificate another replica revoked
// until it happens to re-sign on its own, which with the default 30-day CRL
// validity is weeks away. Storage is the shared truth; this pulls from it.
//
// Which block counts as ours is selectOwnCRL's answer, the same one
// loadCRLCache and readStoredCRL take: the newest CRL this CA signed, wherever
// it sits in the chain. A reader that decided differently from the others would
// cache one list while every re-sign amended another.
//
// Cheap enough to run on a short timer: one CRL read per call and no cluster
// lock. c.mu is never held across the storage read; on the rare tick that finds
// something new it is held for the selection, the comparison, the swap and the
// OCSP eviction. Taking the CRL lock would serialise every replica's poll
// against every revocation for no gain — the swap needs no mutual exclusion
// because it only ever moves forwards, so a poll that raced a local re-sign and
// lost simply declines to install what it read.
//
// It deliberately does not signal crlNotify. That channel exists to tell this
// process's Kubernetes exporter that the published artefacts need rewriting,
// and the replica that actually re-signed has already woken its own exporter
// against the same storage. Signalling here would have every other replica
// re-apply identical content on every revocation in the fleet.
func (c *CA) SyncCRLCache(ctx context.Context) (bool, error) {
	// Read outside c.mu: a storage round-trip must not block the auth path.
	blob, err := c.Storage.GetCRL(ctx)
	if err != nil {
		c.crlSyncFailures.Add(1)
		return false, fmt.Errorf("failed to load CRL: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// SECURITY: install only a CRL this CA signed. The cached CRL is the sole
	// input to the revocation half of every admission decision, so caching a
	// list issued by some other authority would silently unrevoke everything
	// this CA has revoked. selectOwnCRL answers by signature, so a forged CRL
	// cannot get in by carrying a plausible number. Keeping the CRL already held
	// is the fail-closed answer, and the counter says it happened.
	ours, _, err := c.selectOwnCRL(blob)
	if err != nil {
		c.crlSyncFailures.Add(1)
		return false, fmt.Errorf("decoding the stored CRL chain: %w", err)
	}
	if ours == nil {
		c.crlSyncFailures.Add(1)
		return false, fmt.Errorf("the stored CRL chain holds no CRL signed by the CA certificate " +
			"this process is using; keeping the CRL already in memory")
	}

	// Nothing new: the overwhelmingly common outcome, since the job ticks far
	// more often than anything revokes. newerCRL is the same ordering the rest
	// of the package uses, so an unnumbered CRL of ours — openssl's V1 output
	// cannot carry a number — is ordered the same way here as at import.
	if c.cachedCRL != nil && !newerCRL(ours, c.cachedCRL) {
		return false, nil
	}

	previous := c.cachedCRL
	c.cachedCRL = ours
	c.invalidateOCSPForNewlyRevokedLocked(previous, ours)

	slog.Info("Reloaded the CRL from storage",
		"crl_number", ours.Number,
		"revoked", len(ours.RevokedCertificateEntries))
	return true, nil
}

// invalidateOCSPForNewlyRevokedLocked drops the cached OCSP responses for
// serials that the newly loaded CRL revokes and the previous one did not, so
// the responder stops handing out a pre-signed "good" for a certificate
// another replica has just revoked. Without it the CRL would be current while
// OCSP kept answering from responses signed up to OCSPValidity ago.
//
// Only the newly revoked serials are dropped, mirroring what revokeSerialLocked
// does on the replica that performs a revocation. Clearing every revoked
// serial's entry instead would re-sign the whole revoked set on every
// revocation anywhere in the fleet.
//
// c.mu must be held by the caller.
func (c *CA) invalidateOCSPForNewlyRevokedLocked(previous, current *x509.RevocationList) {
	was := make(map[string]struct{})
	if previous != nil {
		for _, entry := range previous.RevokedCertificateEntries {
			was[serialHexStr(entry.SerialNumber)] = struct{}{}
		}
	}
	for _, entry := range current.RevokedCertificateEntries {
		key := serialHexStr(entry.SerialNumber)
		if _, seen := was[key]; !seen {
			delete(c.ocspCache, key)
		}
	}
}

// CachedCRLNumber returns the CRL number of the copy this process is making
// admission decisions from, and whether a CRL is loaded at all. Comparing it
// across replicas is how an operator confirms a revocation has propagated.
func (c *CA) CachedCRLNumber() (*big.Int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedCRL == nil || c.cachedCRL.Number == nil {
		return nil, false
	}
	return new(big.Int).Set(c.cachedCRL.Number), true
}
