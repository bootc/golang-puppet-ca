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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"sort"
	"time"
)

// supersededEntry records one certificate that a renewal has replaced and that
// is to be revoked once its delay has elapsed.
//
// Subject is carried for diagnostics only. Revocation is always by Serial:
// Revoke resolves a subject to its *current* certificate, so revoking by
// subject here would retire the replacement rather than the thing it replaced.
type supersededEntry struct {
	Serial   string    `json:"serial"`
	Subject  string    `json:"subject"`
	RevokeAt time.Time `json:"revoke_at"`
}

// supersedeReplaced retires the certificate identified by oldSerial now that
// subject's replacement has been signed and stored.
//
// Which of the two it does is decided by SupersedeAfter, and the zero value is
// the behaviour every deployment had before this existed:
//
//   - SupersedeAfter <= 0 — revoke immediately, in this call, exactly as the
//     renewal paths used to inline.
//   - SupersedeAfter > 0 — record oldSerial for revocation that far in the
//     future and return. ReconcileSuperseded does the revoking.
//
// Best-effort in both modes: the caller has a signed replacement in hand and a
// failure here must not undo it. Failures are logged, counted into
// supersedeFailures, and returned so the caller can name the path in its own
// log line; no caller treats the error as fatal.
//
// The caller must hold subject's lock and must NOT hold c.mu or the CRL lock:
// both modes acquire the CRL lock themselves, keeping the documented
// subject → crl → c.mu order.
func (c *CA) supersedeReplaced(ctx context.Context, subject, oldSerial string) error {
	if c.SupersedeAfter <= 0 {
		return c.Storage.WithLock(ctx, lockNameCRL, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.revokeSerialLocked(ctx, oldSerial)
		})
	}
	return c.recordSuperseded(ctx, subject, oldSerial, c.SupersedeAfter)
}

// recordSuperseded appends one entry to the pending-revocation list.
//
// The list is durable and shared rather than held in memory for two reasons:
// the replica that signed the replacement may be gone before the delay
// elapses, and nothing else records the fact. It cannot be recovered from the
// inventory either — the inventory says which serials exist for a subject, not
// which of them a renewal retired, nor when the delay started.
//
// The whole read-modify-write runs under the cluster CRL lock, the same lock
// ReconcileSuperseded rewrites the list under. That is what makes the two
// mutual: without it, a sweep landing between this read and this write erases
// the entry, and the certificate it named stays a valid credential for its full
// remaining life with nothing recording that it should not be. The subject lock
// the caller already holds cannot serve — two renewals for *different* subjects
// hold different subject locks and would race each other. Reusing the CRL lock
// rather than introducing a fourth name keeps the lock order at
// subject → crl → c.mu and the SQL connection-nesting depth at two; see
// docs/development/locking.md.
func (c *CA) recordSuperseded(ctx context.Context, subject, serial string, after time.Duration) error {
	if _, ok := new(big.Int).SetString(serial, 16); !ok {
		// Refused here rather than written and discarded by the sweep: the
		// caller is about to log a warning naming this serial, which is a far
		// better place for an operator to see it than a sweep hours later.
		c.supersedeFailures.Add(1)
		return fmt.Errorf("malformed serial %q", serial)
	}
	revokeAt := time.Now().UTC().Add(after)
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		entries, _, err := c.readSuperseded(ctx)
		if err != nil {
			// Appending to what we could not read would write a one-entry list
			// over however many were pending, so every one of those
			// certificates would stay valid with nothing recording otherwise.
			// Corrupt bytes need no such care: readSuperseded returns what it
			// could recover, and the write below is the overwrite they need.
			return err
		}
		entries = append(entries, supersededEntry{
			Serial:   serial,
			Subject:  subject,
			RevokeAt: revokeAt,
		})
		return c.writeSuperseded(ctx, entries)
	})
	if err != nil {
		c.supersedeFailures.Add(1)
		return err
	}
	slog.Info("Recorded superseded certificate for delayed revocation",
		"subject", subject, "serial", serial, "revoke_at", revokeAt.Format(time.RFC3339))
	return nil
}

// ReconcileSuperseded revokes every recorded certificate whose delay has
// elapsed and rewrites the list with the survivors. It reports how many it
// revoked.
//
// Each entry carries its own revoke_at, fixed when the supersession was
// recorded, and this honours that rather than re-deriving it from the current
// configuration. Shortening SupersedeAfter — or setting it back to zero —
// therefore changes what future renewals record, not the window already granted
// to a certificate other parties may be mid-way through replacing; lengthening
// it does not extend one either. What must not depend on the setting is whether
// this runs at all: entries recorded under an earlier configuration have to
// drain whatever the delay is now, or a certificate the operator believes was
// retired stays a live credential for its full remaining life. See
// runSupersededSweeper, which is why the sweep is not gated on the delay.
//
// RevokeOnAutoRenew does not gate this either. That setting decides whether the
// auto-renewal path *records* a supersession at all; once one is on the list
// the replacement has happened and the entry is honoured. Turning the setting
// off does not un-replace certificates already superseded.
//
// Idempotent and self-healing: revoking a serial already in the CRL is a no-op,
// so any replica finishes work another one started, and a pass that fails
// part-way leaves the unfinished entries to be retried on the next.
//
// # Lock discipline
//
// The whole read-modify-write and the revocations it drives run under the
// cluster CRL lock — the same lock recordSuperseded appends under, and the same
// one revokeSerialLocked requires. One acquisition covers all three, so the
// order stays subject → crl → c.mu and this adds no new nesting. On the
// single-node backends the window this closes is invisible; on etcd, Redis or
// SQL — the multi-replica deployments delayed supersession exists for — it is
// real.
func (c *CA) ReconcileSuperseded(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	var revoked int
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		entries, corrupt, err := c.readSuperseded(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			if corrupt {
				// Overwrite rather than return early. Those bytes will never
				// parse, so leaving them re-warns and re-counts on every pass
				// forever — which latches the alert with nothing an operator
				// can do to clear it, and the realistic response to a
				// permanently firing warning is to silence it.
				return c.writeSuperseded(ctx, nil)
			}
			return nil
		}

		now := time.Now().UTC()
		var due, pending []supersededEntry
		for _, e := range entries {
			if now.Before(e.RevokeAt) {
				pending = append(pending, e)
				continue
			}
			due = append(due, e)
		}
		if len(due) == 0 && !corrupt {
			return nil
		}
		// With entries recovered from a corrupt blob the normal path is right:
		// they are swept like any others, and the write-back below persists the
		// survivors — which is the same overwrite the corrupt bytes need.

		// Oldest first, so a pass that runs out of deadline part-way has
		// retired the certificates that have been superseded longest.
		sort.Slice(due, func(i, j int) bool { return due[i].RevokeAt.Before(due[j].RevokeAt) })

		var (
			failed    []supersededEntry
			discarded int
		)
		func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, e := range due {
				if _, ok := new(big.Int).SetString(e.Serial, 16); !ok {
					// Retrying is right for a transient failure and wrong for a
					// permanent one. A serial that is not parseable hex can
					// never be revoked, so carrying it forward would retry it
					// on every pass forever, latching both this counter's alert
					// and the CRL one with nothing an operator could do to clear
					// them. Discarded, loudly — and never handed to
					// revokeSerialLocked, so it does not count as a CRL failure
					// as well.
					slog.Error("Discarding superseded-certificate entry with a malformed serial; "+
						"it can never be revoked", "serial", e.Serial, "subject", e.Subject)
					discarded++
					continue
				}
				if err := c.revokeSerialLocked(ctx, e.Serial); err != nil {
					// Per entry, not all-or-nothing: one failure must not stall
					// the revocations behind it, which would leave each of those
					// certificates a valid credential indefinitely.
					slog.Warn("Could not revoke superseded certificate; will retry",
						"subject", e.Subject, "serial", e.Serial, "error", err)
					failed = append(failed, e)
					continue
				}
				revoked++
				slog.Info("Revoked superseded certificate", "subject", e.Subject, "serial", e.Serial)
			}
		}()
		if len(failed) > 0 || discarded > 0 {
			c.supersedeFailures.Add(1)
		}
		return c.writeSuperseded(ctx, append(pending, failed...))
	})
	return revoked, err
}

// PendingSupersessions returns the number of certificates currently recorded
// for delayed revocation, for diagnostics and metrics. An absent list is zero.
//
// It takes no cluster lock: a count read a moment before a sweep is still a
// useful count, and blocking a metrics scrape behind a CRL re-sign is not a
// trade worth making.
//
// It also neither logs nor counts a corrupt list, deliberately — it is called
// on a scrape interval, and a blob that will never parse would otherwise emit
// the same warning and increment the same counter every few seconds until an
// operator noticed. The sweep is what reports that condition, once per pass,
// and it is also what clears it. A corrupt list is counted here as whatever
// decoded before the failure, which under-reports; the counter is where the
// discrepancy shows up.
func (c *CA) PendingSupersessions(ctx context.Context) (int, error) {
	data, err := c.loadSuperseded(ctx)
	if err != nil {
		return 0, err
	}
	entries, _ := parseSuperseded(data)
	return len(entries), nil
}

// SupersedeFailures returns the number of times the CA failed to schedule or
// carry out a delayed revocation: a supersession it could not record, and each
// sweep that left an entry unrevoked or discarded one it never could revoke. A
// rising value means a certificate a renewal replaced may still be a valid
// credential; the metrics exporter surfaces it as
// puppetca_supersede_failures_total.
func (c *CA) SupersedeFailures() uint64 {
	return c.supersedeFailures.Load()
}

// readSuperseded loads the pending-revocation list.
//
// An absent list is empty and not an error: that is the steady state before the
// first supersession, and on any CA whose delay has never been enabled. A read
// that *fails* is reported, because both mutating callers go on to write the
// list back — and a failed read reported as "empty" would have them persist an
// empty list over entries that are still there, silently un-scheduling every
// pending revocation.
//
// An unparseable list is treated as recoverable-then-empty, deliberately and
// with a warning: whatever decoded before the failure is real, revocable
// serials and is returned, while the rest is unrecoverable. Failing closed on
// corrupt bytes would refuse renewals over a certificate that at worst stays
// valid until it expires.
//
// The corrupt return says the bytes were unusable, as distinct from absent. A
// caller that can write must overwrite them: an unparseable blob is not
// self-clearing, and left alone it re-warns on every pass forever.
func (c *CA) readSuperseded(ctx context.Context) (entries []supersededEntry, corrupt bool, err error) {
	data, err := c.loadSuperseded(ctx)
	if err != nil {
		return nil, false, err
	}
	entries, perr := parseSuperseded(data)
	if perr != nil {
		// entries keeps whatever decoded before the failure: encoding/json
		// fills the slice as it goes. Those are real serials, so they are
		// returned rather than discarded — the sweep retires them normally and
		// its write-back drops only the part that will never parse.
		//
		// Counted, because however many entries these bytes named, they are
		// gone: nothing can rediscover them, so those certificates stay valid
		// for their full remaining life with nothing recording that they should
		// not be. Left uncounted, the one alert that bounds that exposure could
		// not fire.
		//
		// The raw bytes are logged because this is the one arm that can name no
		// serial — there may have been several, and the sweep is about to
		// overwrite them. The blob holds only hex serials, subject names and
		// RFC 3339 timestamps, all of which are already in the inventory; it is
		// truncated in case the corruption made it large.
		c.supersedeFailures.Add(1)
		slog.Warn("Discarding unparseable pending certificate revocations; whatever they named "+
			"will not be scheduled for revocation",
			"error", perr, "recovered", len(entries), "raw", truncateForLog(data))
		return entries, true, nil
	}
	return entries, false, nil
}

// loadSuperseded fetches the stored list's raw bytes. An absent list yields
// (nil, nil): that is the steady state before the first supersession, and
// parseSuperseded decodes nil to an empty list.
func (c *CA) loadSuperseded(ctx context.Context) ([]byte, error) {
	data, err := c.Storage.GetSuperseded(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		// Without the backend's error text: a SQL driver's connection error can
		// carry the DSN, and this error reaches a Warn line on the renewal path.
		return nil, errors.New("reading pending certificate revocations")
	}
	return data, nil
}

// parseSuperseded decodes the stored list, returning whatever decoded before a
// failure alongside the failure. Pure: it neither logs nor counts, so callers
// on a scrape interval can use it without turning one corrupt blob into a
// stream of identical warnings. Absent or empty bytes decode to no entries and
// no error.
func parseSuperseded(data []byte) ([]supersededEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var entries []supersededEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return entries, err
	}
	return entries, nil
}

// writeSuperseded persists the pending-revocation list. An empty list is
// written as `[]` rather than deleted: one key that is always present is easier
// for a backup or a migration to reason about than one that comes and goes.
func (c *CA) writeSuperseded(ctx context.Context, entries []supersededEntry) error {
	if len(entries) == 0 {
		entries = []supersededEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encoding pending certificate revocations: %w", err)
	}
	if err := c.Storage.SaveSuperseded(ctx, data); err != nil {
		// Without the backend's error text, for the reason readSuperseded
		// gives: both reach the same Warn line on the renewal path.
		return errors.New("saving pending certificate revocations")
	}
	return nil
}

// truncateForLog bounds a stored blob before it reaches a log line, so a
// corrupt or maliciously large value cannot flood the log.
func truncateForLog(data []byte) string {
	const max = 1024
	if len(data) <= max {
		return string(data)
	}
	return string(data[:max]) + "...(truncated)"
}
