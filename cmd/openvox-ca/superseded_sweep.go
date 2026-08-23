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

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// runSupersededSweeper periodically revokes the certificates that renewals
// have replaced and whose delay (superseded_cert_revoke_after_sec) has since
// elapsed.
//
// It runs whatever that delay is set to, including zero, and that is the point.
// The switch that fills the list is not the switch that drains it: an operator
// who grants a window, accrues entries and then sets the delay back to zero
// still has certificates on the list, each with its own recorded due time. A
// sweep gated on the delay would strand exactly those — every one of them a
// credential the operator believes was retired, kept valid for its full
// remaining life by the setting change that was meant to tighten things up.
//
// The idle cost that makes running it unconditionally reasonable is one
// absent-key read per replica per interval, and no cluster lock at all:
// ReconcileSuperseded rules the work out before acquiring one, precisely so
// that the deployments which never enable a window do not take a cluster-wide
// lock four times an hour forever to discover there is nothing to do.
//
// Replica safety: CA.ReconcileSuperseded does its list read-modify-write and
// its revocations under the shared cluster CRL lock, so when this runs on
// multiple replicas only the first to acquire the lock revokes; the others
// observe an already-drained list and revoke nothing. No leader election is
// required.
//
// It returns when ctx is cancelled (i.e. on shutdown).
func runSupersededSweeper(ctx context.Context, c *ca.CA, interval, revokeAfter time.Duration) {
	slog.Info("Starting superseded-certificate revocation sweep",
		"interval", interval, "revoke_after", revokeAfter)

	// Run immediately at startup so a backlog that came due while every replica
	// was down is cleared without waiting a full interval — that backlog is the
	// case where certificates have been outliving their window the longest.
	sweepSupersededOnce(ctx, c)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Superseded-certificate revocation sweep stopping")
			return
		case <-ticker.C:
			sweepSupersededOnce(ctx, c)
		}
	}
}

// sweepSupersededOnce runs a single sweep, logging the outcome. Errors are
// logged and swallowed so a transient storage/lock failure does not stop the
// job; the next tick retries, and ReconcileSuperseded leaves anything it could
// not revoke on the list for exactly that.
func sweepSupersededOnce(ctx context.Context, c *ca.CA) {
	revoked, err := c.ReconcileSuperseded(ctx)
	switch {
	case err != nil:
		// revoked can be non-zero here: entries are revoked one at a time and
		// the pass reports what it managed before the failure.
		slog.Warn("Superseded-certificate revocation sweep failed", "revoked", revoked, "error", err)
	case revoked > 0:
		slog.Info("Superseded certificates revoked", "revoked", revoked)
	default:
		slog.Debug("Superseded-certificate revocation sweep: nothing due")
	}
}
