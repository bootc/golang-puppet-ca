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
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// k8sExportRetryInterval is how long a failed export cycle waits before it is
// retried. Exports are otherwise driven only by startup and CRL updates, which
// on a low-churn CA can be weeks apart, so without a retry a single transient
// storage or API-server error leaves every target holding a stale CA
// certificate or CRL until the CRL next changes.
//
// Two minutes sits well inside k8sExportFailingFor (15m), the debounce on
// PuppetCAKubernetesExportFailing: a cycle that recovers on the first retry
// resolves before the alert would have paged, while one that keeps failing
// keeps re-stamping last_error and stays firing.
const k8sExportRetryInterval = 2 * time.Minute

// runK8sExporter publishes the CA certificate and CRL into the configured
// Kubernetes Secrets/ConfigMaps. It exports once at startup (reconciling state
// after restarts, config changes, or a CA import) and then re-exports whenever
// the CRL is updated (revoke, reissue, background refresh, or expired-cert
// cleanup), so CRL-bearing objects stay current.
//
// A cycle in which any target failed is retried after retryInterval, and keeps
// being retried until one succeeds completely. The CRL-update signal alone is
// not enough: it can be weeks away on a quiet CA, which would leave a target
// stale for that long after a momentary failure.
//
// It runs in the frontend process, reading the cert/CRL through the storage
// service. Export failures are logged and swallowed: the export is auxiliary
// and must never take down the CA. It returns when ctx is cancelled (i.e. on
// shutdown).
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter, retryInterval time.Duration) {
	slog.Info("Starting Kubernetes export job", "retry_interval", retryInterval)

	// Created disarmed; armed only while the last cycle failed. Go 1.23+ timer
	// semantics mean Stop and Reset need no channel drain, and a fire that
	// races with Stop cannot be received afterwards.
	retry := time.NewTimer(retryInterval)
	retry.Stop()
	defer retry.Stop()

	// runCycle exports once and re-arms (or disarms) the retry timer to match
	// the outcome, so a recovered cycle stops retrying and a still-failing one
	// keeps going.
	runCycle := func() {
		retry.Stop()
		if !exportK8sOnce(ctx, exporter) {
			retry.Reset(retryInterval)
		}
	}

	runCycle()

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Kubernetes export job stopping")
			return
		case <-c.CRLUpdated():
			slog.Debug("CRL updated, re-exporting to Kubernetes")
			runCycle()
		case <-retry.C:
			slog.Debug("Retrying failed Kubernetes export cycle")
			runCycle()
		}
	}
}

// exportK8sOnce runs a single reconcile, logging the outcome, and reports
// whether every target succeeded. Per-target errors are already logged by
// ExportAll; here we log only that the cycle had failures.
func exportK8sOnce(ctx context.Context, exporter *k8sexport.Exporter) bool {
	if err := exporter.ExportAll(ctx); err != nil {
		slog.Warn("Kubernetes export cycle completed with errors", "error", err)
		return false
	}
	slog.Debug("Kubernetes export cycle complete")
	return true
}
