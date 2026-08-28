{
  prometheusAlerts+:: {
    groups+: [
      {
        name: 'openvox-ca-availability',
        rules: [
          {
            alert: 'PuppetCAExporterDown',
            // 'up == 0' only matches an existing series; if the target is absent
            // from service discovery entirely there is no 'up' series to compare,
            // so OR in absent() to catch a wholly-missing exporter too.
            expr: |||
              up{%(selector)s} == 0
              or
              absent(up{%(selector)s})
            ||| % { selector: $._config.puppetCASelector },
            'for': $._config.downFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA metrics exporter is down.',
              description: 'Prometheus cannot scrape the Puppet CA exporter on {{ $labels.instance }}. Certificate and CRL expiry can no longer be monitored.',
            },
          },
          {
            alert: 'PuppetCAScrapeFailing',
            // The exporter answered but could not read CA state from storage.
            expr: 'puppetca_collector_scrape_success{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.scrapeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA exporter cannot read CA state.',
              description: 'The Puppet CA exporter on {{ $labels.instance }} is failing to gather certificate metrics from storage (puppetca_collector_scrape_success=0).',
            },
          },
          {
            alert: 'PuppetCANotReady',
            expr: 'puppetca_ca_ready{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.readyFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is not ready.',
              description: 'The Puppet CA on {{ $labels.instance }} has been reporting not-ready (puppetca_ca_ready=0) and cannot serve signing requests.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-certificate-expiry',
        rules: [
          {
            alert: 'PuppetCACertificateExpiringSoon',
            expr: |||
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.caExpiryWarningSeconds,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate is approaching expiry.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCACertificateExpiringCritical',
            expr: 'puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(crit)d' % {
              selector: $._config.puppetCASelector,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate expires imminently.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}. Re-keying the CA is disruptive; act now.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-expiry',
        rules: [
          {
            alert: 'PuppetCACRLExpiringSoon',
            expr: |||
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.crlExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL is approaching its NextUpdate.',
              description: 'The CRL on {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. The CA normally auto-refreshes it; check the CRL refresher.',
            },
          },
          {
            alert: 'PuppetCACRLExpired',
            expr: 'puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL has expired.',
              description: 'The CRL on {{ $labels.instance }} is past its NextUpdate. Relying parties may reject it and fail revocation checks.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-leaf-certificates',
        rules: [
          {
            alert: 'PuppetCALeafCertificateExpiringSoon',
            // state!="revoked" excludes certificates that have been revoked: a
            // revoked cert nearing expiry is expected and not actionable.
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(warn)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.leafExpiryWarningSeconds,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate is approaching expiry.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}. The node may have stopped renewing.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpiringCritical',
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(crit)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate expires imminently.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpired',
            expr: 'puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A non-revoked leaf certificate has expired.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) on {{ $labels.instance }} has expired but is not revoked.',
            },
          },
          {
            alert: 'PuppetCACertificateRequestPending',
            expr: 'puppetca_leaf_certificate_info{%(selector)s,state="requested"} == 1' % { selector: $._config.puppetCASelector },
            'for': $._config.pendingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A certificate request has been pending too long.',
              description: 'The request for {{ $labels.subject }} on {{ $labels.instance }} has been awaiting signing for more than %(pendingFor)s.' % { pendingFor: $._config.pendingFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-maintenance',
        rules: [
          {
            alert: 'PuppetCACRLUpdateFailing',
            // The CA failed to amend the CRL — a CRL it could not re-sign,
            // write or read, on any of the four paths that write one (revoke,
            // reissue, refresh or expired-cert cleanup). Some callers swallow
            // this (e.g. the best-effort revoke of a superseded cert on
            // renewal), so a revoked/superseded certificate may remain valid.
            // Not every revocation that missed the CRL lands here, and which
            // ones do depends on the backend: one refused at a lock
            // acquisition fails ahead of any CRL work and is logged only —
            // every backend's cross-node acquisition, and on filesystem/SQLite
            // a wait for another process on the host — while on
            // filesystem/SQLite a revocation that merely queued behind an
            // issuance in this same process past lockTimeout fails at its first
            // storage read and is counted: a benign cause worth ruling out
            // first on those backends. See docs/metrics.md. The counter resets on restart, so
            // alert on increase() over a window rather than a raw value.
            expr: 'increase(puppetca_crl_update_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlUpdateWindow,
            },
            'for': $._config.crlUpdateFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to update its CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} could not amend its CRL (puppetca_crl_update_failures_total is rising). Revocations may not have taken effect and superseded certificates may still be valid. Check the CA logs to tell the causes apart: "Renew:"/"AutoRenew: failed to revoke replaced certificate"/"Clean:" warnings are a real failure to maintain the CRL, and on filesystem or SQLite a "Revoke failed" warning on a request that took over a minute is instead a revocation that merely queued too long for its subject lock. Then check CRL storage.',
            },
          },
          {
            alert: 'PuppetCACRLSyncFailing',
            // This replica could not reload the stored CRL into the copy its
            // revocation checks read: an unreadable CRL, or one signed by a
            // different CA certificate than the one this process loaded (the
            // usual cause of the latter is a rotated CA certificate on a replica
            // that has not restarted). Counter resets on restart, so alert on
            // increase() over a window. It leads the lag alert below by design —
            // this says why a replica is falling behind, that one says it has.
            expr: 'increase(puppetca_crl_sync_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlSyncWindow,
            },
            'for': $._config.crlSyncFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA cannot reload its CRL from storage.',
              description: 'The Puppet CA on {{ $labels.instance }} could not reload the stored CRL (puppetca_crl_sync_failures_total is rising), so it is enforcing whichever CRL it already held. A certificate revoked on another replica may still be accepted here. Check CRL storage, and whether the CA certificate was replaced without restarting this replica.',
            },
          },
          {
            alert: 'PuppetCACRLStale',
            // The revocation list this replica enforces is behind the stored
            // one. Every replica polls storage on crl_sync_interval_sec, so a
            // gap is normal for a moment after each revocation and abnormal
            // beyond crlLagFor.
            //
            // Both series come from the same exporter, so this compares an
            // instance against itself rather than against the fleet — no fan-in,
            // and it fires on the replica that is actually stale. Subtracting
            // rather than comparing makes $value the size of the gap; a bare
            // '>' would report the stored number instead.
            //
            // The second arm exists because the two series go missing for
            // different reasons, and a subtraction over a missing operand is
            // silence rather than an alert. The exporter drops
            // puppetca_crl_number whenever the stored CRL cannot be read or
            // parsed, while still publishing the cached number — and an
            // unreadable stored CRL is one of the two conditions this rule is
            // meant to page on, so without the arm the worst case would be the
            // quiet one.
            //
            // It is qualified on a successful scrape so that arm covers only
            // the CRL being unreadable, not the whole gather failing: a storage
            // outage drops the same series and is already paged by
            // PuppetCAScrapeFailing, and one cause should not raise two alerts.
            // The reverse asymmetry (cached absent, stored present) means the
            // replica has no CRL in memory at all and is covered by
            // PuppetCANotReady, so it is deliberately left out.
            expr: |||
              puppetca_crl_number{%(selector)s} - puppetca_crl_cached_number{%(selector)s} > 0
              or
              (puppetca_crl_cached_number{%(selector)s}
                 unless puppetca_crl_number{%(selector)s})
                and on(instance) puppetca_collector_scrape_success{%(selector)s} == 1
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.crlLagFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA replica is enforcing an out-of-date CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} has not caught up with the CRL in storage for more than %(crlLagFor)s, so certificates revoked on another replica are still being accepted here. Either it is behind the stored CRL, or the stored CRL cannot be read at all (in which case puppetca_crl_number is absent for this instance). Check puppetca_crl_sync_failures_total and the CA logs. A restart reloads the CRL, selecting the newest block this CA signed; if the stored chain carries none, startup warns and the re-sign paths refuse it, so check the stored chain rather than restarting repeatedly.' % { crlLagFor: $._config.crlLagFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-kubernetes-export',
        rules: [
          {
            alert: 'PuppetCAKubernetesExportFailing',
            // The most recent apply attempt for a target failed. Exports are
            // event-driven (startup, CRL updates, and a retry after a failed
            // cycle) and can be days apart on a quiet CA, so this compares
            // last-error/last-success timestamps — a state that persists until
            // a retry succeeds — rather than a rate window, which would
            // silently resolve between attempts. The 'unless' arm catches a
            // target that has never succeeded at all.
            //
            // Both arms have last_error on the left, so this rule can only fire
            // for a target the exporter has actually written a series for. That
            // is a contract on the exporter, not an accident: ExportAll must
            // record a metric for every target on every cycle, whatever failed
            // upstream. It once returned before the per-target loop when a
            // material read failed, which wrote no series at all and made this
            // alert unable to report the very outage it exists for.
            // PuppetCAKubernetesExportNotRunning below is the backstop for that
            // whole class, and mixin/tests.yaml exercises both.
            expr: |||
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                > puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
              or
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                unless puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.k8sExportFailingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target is failing to apply.',
              description: 'The most recent apply of {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} from {{ $labels.instance }} failed; the exported object may hold a stale CA certificate or CRL until the next successful export. Check the CA logs, RBAC, and API server connectivity.',
            },
          },
          {
            alert: 'PuppetCAKubernetesExportNotRunning',
            // A configured target that has never been attempted at all. This
            // is where the two export rules' division of labour is argued;
            // ExportAll and InitTargetMetrics in internal/k8sexport state the
            // invariant they enforce and point here. The separate decision to
            // leave the last_success/last_error gauges unpublished is argued
            // where it is made, at initTargets in internal/k8sexport/metrics.go
            // and, for operators, in docs/metrics.md.
            //
            // Every arm of PuppetCAKubernetesExportFailing has last_error on
            // its left, so that rule can only speak about a target the CA has
            // recorded a result for. It is structurally silent when the CA
            // records nothing — and no PromQL comparison matches an absence, so
            // no reshaping of that expression can fix it from this side. The
            // answer has to come from the CA: publish a series for a target
            // that has done nothing, and "nothing has happened" becomes a value
            // that can be tested.
            //
            // So the CA publishes puppetca_k8s_export_applies_total at zero for
            // every configured target before the first cycle runs, and also on
            // the path where the export gives up before starting — an
            // in-cluster client it cannot build, a pod namespace it cannot
            // resolve. That path is the one worth the trouble: the CA stays up,
            // readiness stays green, the exported objects quietly stop being
            // updated, and a single log line is otherwise the only trace.
            //
            // `without (result)` rather than a `by` allowlist. Both collapse
            // the success/error pair, but an allowlist also discards every
            // label it does not name -- and under the chart's own defaults the
            // label it would keep is not the one it looks like. The shipped
            // ServiceMonitor sets honorLabels: false, so Prometheus resolves
            // the collision on `namespace` in the target's favour and renames
            // the exporter's to `exported_namespace`. A `by (… namespace …)`
            // clause would then group on the CA pod's namespace, identical for
            // every target, and drop the export namespace entirely -- so two
            // targets differing only by namespace, which is the documented way
            // to publish one trust bundle into several, would share a group and
            // an attempted sibling would mask a never-attempted one. `without`
            // keeps whatever labels the deployment actually attached, and
            // leaves this rule carrying the same label set as
            // PuppetCAKubernetesExportFailing so the pair routes and silences
            // alike.
            //
            // Collapsing 'result' means a target that is attempted and always
            // fails is not caught here
            // (that is Failing's job, and the two cannot both fire: a zero sum
            // means no result was ever recorded, so there is no last_error for
            // Failing to match). Only a target attempted zero times matches.
            // The counter resets to zero on restart and the startup export runs
            // immediately, so k8sExportNotRunningFor only has to outlast a slow
            // start.
            //
            // It does not cover a crashlooping CA, and must not be read as
            // doing so. A pod that keeps restarting fails scrapes; Prometheus
            // writes staleness markers, the instance stops being returned, and
            // this rule's 'for' clock resets rather than accumulating. That is
            // PuppetCAExporterDown's job (downFor, 5m), and it is the better
            // alert for it. What this rule covers is the opposite shape: a CA
            // that stays up, scrapes cleanly, and reports readiness while its
            // export job does nothing.
            expr: |||
              sum without (result) (
                puppetca_k8s_export_applies_total{%(selector)s}
              ) == 0
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.k8sExportNotRunningFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target has never been attempted.',
              description: 'The Puppet CA on {{ $labels.instance }} has {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} configured for export but has not attempted a single apply in %(k8sExportNotRunningFor)s. The exported object holds whatever it held before, and PuppetCAKubernetesExportFailing cannot report on a target with no apply results. Check the CA logs for the Kubernetes export job starting, and for errors initialising the in-cluster client.' % { k8sExportNotRunningFor: $._config.k8sExportNotRunningFor },
            },
          },
        ],
      },
    ],
  },
}
