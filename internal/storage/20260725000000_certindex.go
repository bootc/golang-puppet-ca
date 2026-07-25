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

package storage

import (
	"context"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

// Migration 20260725000000 (certindex): grow the inventory table into the
// certificate index backing the CertIndex capability (see sqlInventoryRow for
// the column semantics).
//
// Existing rows get state='signed' via the column default and NULL projection
// columns; both are reconciled from the authoritative artefacts (stored PEMs
// and the signed CRL) by the CA's index repair pass at startup, so this
// migration needs no data backfill of its own.
//
// The state and not_after indices are provisioned ahead of their consumers,
// deliberately: no shipped query filters on either column yet (the statuses
// handler filters state in Go to keep its dedup set complete, and no
// expiry-window query exists), but issue #137 fixes this schema before 1.0.0
// precisely because changing it later means another migration on live
// databases. Two low-cardinality index maintenances per issuance is the
// price of not re-migrating when a state-filtered or expiry-window consumer
// lands.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		// bun's dialects map time.Time to different column types; mirror the
		// type CreateTable-from-model would have produced so an upgraded table
		// is indistinguishable from a freshly created one.
		timeType := "TIMESTAMP"
		switch db.Dialect().Name() {
		case dialect.PG:
			timeType = "TIMESTAMPTZ"
		case dialect.MySQL:
			timeType = "DATETIME"
		}

		columns := []string{
			"fingerprint_sha256 VARCHAR(95)",
			"dns_alt_names TEXT",
			"auth_extensions TEXT",
			"state VARCHAR(16) NOT NULL DEFAULT 'signed'",
			"revoked_at " + timeType,
		}
		for _, col := range columns {
			if _, err := db.NewAddColumn().
				Model((*sqlInventoryRow)(nil)).
				ColumnExpr(col).
				Exec(ctx); err != nil {
				return err
			}
		}

		if _, err := db.NewCreateIndex().
			Model((*sqlInventoryRow)(nil)).
			Index("idx_puppet_ca_inventory_state").
			Column("state").
			Exec(ctx); err != nil {
			return err
		}
		if _, err := db.NewCreateIndex().
			Model((*sqlInventoryRow)(nil)).
			Index("idx_puppet_ca_inventory_not_after").
			Column("not_after").
			Exec(ctx); err != nil {
			return err
		}
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		// bun's DropIndexQuery emits bare "DROP INDEX <name>", which MySQL
		// rejects (it requires "... ON <table>"), so build the statement per
		// dialect.
		for _, idx := range []string{"idx_puppet_ca_inventory_not_after", "idx_puppet_ca_inventory_state"} {
			stmt := "DROP INDEX " + idx
			if db.Dialect().Name() == dialect.MySQL {
				stmt += " ON puppet_ca_inventory"
			}
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		for _, col := range []string{"revoked_at", "state", "auth_extensions", "dns_alt_names", "fingerprint_sha256"} {
			if _, err := db.NewDropColumn().
				Model((*sqlInventoryRow)(nil)).
				ColumnExpr(col).
				Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}
