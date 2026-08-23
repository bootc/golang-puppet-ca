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

package k8sexport

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metricsNamespace matches the namespace used by internal/metrics so the
// export series appear alongside the other puppetca_* metrics.
const (
	metricsNamespace = "puppetca"
	metricsSubsystem = "k8s_export"
)

// Metrics instruments the exporter's apply attempts. Export failures are
// otherwise only logged (the export is auxiliary and never stops the CA), so
// these series are the way to alert on a target that persistently fails.
// Label cardinality is bounded by the configured targets.
type Metrics struct {
	applies     *prometheus.CounterVec
	lastSuccess *prometheus.GaugeVec
	lastError   *prometheus.GaugeVec
}

// NewMetrics constructs the exporter's metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		applies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "applies_total",
			Help:      "Kubernetes export apply attempts, by target object and result (success or error).",
		}, []string{"kind", "namespace", "name", "result"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_success_timestamp_seconds",
			Help:      "Time of the last successful apply for each Kubernetes export target.",
		}, []string{"kind", "namespace", "name"}),
		lastError: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_error_timestamp_seconds",
			Help:      "Time of the last failed apply for each Kubernetes export target. Compare against last_success to detect a target whose most recent apply failed; exports are event-driven, so rate-based alerts would resolve between attempts.",
		}, []string{"kind", "namespace", "name"}),
	}
	reg.MustRegister(m.applies, m.lastSuccess, m.lastError)
	return m
}

// initTargets creates the applies_total children for every configured target,
// at zero, before the first export runs. A nil receiver (metrics disabled) is a
// no-op.
//
// Prometheus omits a child that has never been touched, so without this an
// exporter that records nothing at all — a wedged goroutine, or a regression
// that returns from ExportAll before the per-target loop — is indistinguishable
// from an exporter that is not configured. Both look like "no series", and
// every arm of PuppetCAKubernetesExportFailing needs a series to match on.
// Pre-creating these at zero gives PuppetCAKubernetesExportNotRunning something
// to alert on: the target is configured, the process is up, and no apply has
// ever been attempted.
//
// Only applies_total is pre-created. The last_success/last_error gauges must
// stay absent until something actually happens: initialising them to zero would
// make last_error{...} unless last_success{...} match nothing, silencing the
// arm that catches a target which has never succeeded.
func (m *Metrics) initTargets(targets []Target, namespaceFor func(*Target) string) {
	if m == nil {
		return
	}
	for i := range targets {
		t := &targets[i]
		ns := namespaceFor(t)
		m.applies.WithLabelValues(t.Kind, ns, t.Metadata.Name, "success")
		m.applies.WithLabelValues(t.Kind, ns, t.Metadata.Name, "error")
	}
}

// recordApply counts one apply attempt for a target in the given (resolved)
// namespace. A nil receiver (metrics disabled) is a no-op.
func (m *Metrics) recordApply(t *Target, namespace string, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.applies.WithLabelValues(t.Kind, namespace, t.Metadata.Name, result).Inc()
	if err == nil {
		m.lastSuccess.WithLabelValues(t.Kind, namespace, t.Metadata.Name).SetToCurrentTime()
	} else {
		m.lastError.WithLabelValues(t.Kind, namespace, t.Metadata.Name).SetToCurrentTime()
	}
}
