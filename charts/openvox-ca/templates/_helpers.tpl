{{/*
Chart name, overridable, truncated to the 63-char label limit.
*/}}
{{- define "openvox-ca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Release names that already contain the chart name are
not doubled up, so `helm install openvox-ca` yields "openvox-ca" rather than
"openvox-ca-openvox-ca".
*/}}
{{- define "openvox-ca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "openvox-ca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openvox-ca.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "openvox-ca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openvox-ca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "openvox-ca.labels" -}}
helm.sh/chart: {{ include "openvox-ca.chart" . }}
{{ include "openvox-ca.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: certificate-authority
app.kubernetes.io/part-of: openvox
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "openvox-ca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "openvox-ca.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Container image reference.

A digest wins over a tag. An explicit tag is used verbatim — that is how you
select the CentOS Stream variant, whose tags carry no suffix. With neither set,
the default is the Alpine variant of the chart's appVersion; a -dev appVersion
means the chart was built from an unreleased tree, whose published image is the
rolling "edge" tag rather than a version that exists in the registry.
*/}}
{{- define "openvox-ca.image" -}}
{{- $ref := .Values.image.repository -}}
{{- if .Values.image.registry -}}
{{- $ref = printf "%s/%s" .Values.image.registry .Values.image.repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $ref .Values.image.digest -}}
{{- else -}}
{{- $tag := .Values.image.tag -}}
{{- if not $tag -}}
{{- $base := .Chart.AppVersion -}}
{{- if hasSuffix "-dev" $base -}}
{{- $base = "edge" -}}
{{- end -}}
{{- $tag = printf "%s-alpine" $base -}}
{{- end -}}
{{- printf "%s:%s" $ref $tag -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ConfigMap holding config.yaml and its companion files.
*/}}
{{- define "openvox-ca.configMapName" -}}
{{- default (include "openvox-ca.fullname" .) .Values.existingConfigMap -}}
{{- end -}}

{{- define "openvox-ca.pvcName" -}}
{{- default (include "openvox-ca.fullname" .) .Values.persistence.existingClaim -}}
{{- end -}}

{{/*
Paths of the files the chart renders into the config ConfigMap.
*/}}
{{- define "openvox-ca.puppetServerFilePath" -}}
{{- printf "%s/puppet-server" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{- define "openvox-ca.autosignFilePath" -}}
{{- printf "%s/autosign.conf" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{- define "openvox-ca.configFilePath" -}}
{{- printf "%s/config.yaml" (trimSuffix "/" .Values.configMount) -}}
{{- end -}}

{{/*
The server's config.yaml.

Starts from what the chart's convenience blocks imply — cadir, listen address,
mounted TLS/CA paths, the metrics listener, the export targets — then merges
.Values.config over the top, so an explicit config key always wins.
*/}}
{{- define "openvox-ca.config" -}}
{{- $c := dict -}}
{{- $_ := set $c "cadir" .Values.persistence.mountPath -}}
{{- $_ := set $c "host" .Values.listen.host -}}
{{- $_ := set $c "port" (.Values.listen.port | int) -}}
{{/*
  verbosity goes through the config file rather than a --verbosity flag: a
  flag would outrank the file unconditionally, which would make
  config.verbosity silently ineffective and break the chart's "config always
  wins" contract for that one key.
*/}}
{{- $_ := set $c "verbosity" (.Values.verbosity | int) -}}
{{- if .Values.tls.existingSecret -}}
{{- $_ := set $c "tls_cert" (printf "%s/%s" (trimSuffix "/" .Values.tls.mountPath) .Values.tls.certKey) -}}
{{- $_ := set $c "tls_key" (printf "%s/%s" (trimSuffix "/" .Values.tls.mountPath) .Values.tls.keyKey) -}}
{{- end -}}
{{- if .Values.ca.existingSecret -}}
{{- $_ := set $c "ca_cert_file" (printf "%s/%s" (trimSuffix "/" .Values.ca.mountPath) .Values.ca.certKey) -}}
{{- $_ := set $c "ca_key_file" (printf "%s/%s" (trimSuffix "/" .Values.ca.mountPath) .Values.ca.keyKey) -}}
{{- end -}}
{{- if .Values.caKeyPassphrase.existingSecret -}}
{{- $_ := set $c "encrypt_ca_key" true -}}
{{- $_ := set $c "ca_key_passphrase_file" (printf "%s/%s" (trimSuffix "/" .Values.caKeyPassphrase.mountPath) .Values.caKeyPassphrase.key) -}}
{{- end -}}
{{- if .Values.puppetServers -}}
{{- $_ := set $c "puppet_server_file" (include "openvox-ca.puppetServerFilePath" .) -}}
{{- end -}}
{{- if .Values.autosign.patterns -}}
{{- $_ := set $c "autosign_config" (include "openvox-ca.autosignFilePath" .) -}}
{{- else if .Values.autosign.mode -}}
{{- $_ := set $c "autosign_config" (.Values.autosign.mode | toString) -}}
{{- end -}}
{{- if .Values.metrics.enabled -}}
{{- $_ := set $c "metrics_listen" (printf "%s:%v" .Values.metrics.host .Values.metrics.port) -}}
{{- end -}}
{{- if .Values.kubernetesExport.enabled -}}
{{- $ke := dict "targets" .Values.kubernetesExport.targets -}}
{{- if .Values.kubernetesExport.fieldManager -}}
{{- $_ := set $ke "field_manager" .Values.kubernetesExport.fieldManager -}}
{{- end -}}
{{- $_ := set $c "kubernetes_export" $ke -}}
{{- end -}}
{{- toYaml (mergeOverwrite $c (deepCopy .Values.config)) -}}
{{- end -}}

{{/*
The rendered contents of the config ConfigMap, as a filename -> body map. Used
both by the ConfigMap itself and by the pod-template checksum annotation.
*/}}
{{- define "openvox-ca.configMapData" -}}
config.yaml: |
{{ include "openvox-ca.config" . | indent 2 }}
{{- if .Values.puppetServers }}
puppet-server: |
{{- range .Values.puppetServers }}
  {{ . }}
{{- end }}
{{- end }}
{{- if .Values.autosign.patterns }}
autosign.conf: |
{{- range .Values.autosign.patterns }}
  {{ . }}
{{- end }}
{{- end }}
{{- range $name, $body := .Values.extraConfigFiles }}
{{- /* Quoted so a key can never contribute YAML structure, whatever the guard in
       openvox-ca.validate lets through. Left-trimmed only: trimming both sides
       eats the newline before the key, and trimming neither emits a blank line
       into the rendered ConfigMap once per entry. */}}
{{ $name | quote }}: |
{{ $body | trimSuffix "\n" | indent 2 }}
{{- end }}
{{- end -}}

{{/*
Whether the pod needs to talk to the Kubernetes API: for the export feature, or
for OpenBao's native Kubernetes auth (which reads the projected SA token).

Reads the *merged* config, not .Values.config, so that export targets and an
openbao auth_method supplied through `config.kubernetes_export` /
`config.openbao` count — the server treats export as enabled whenever targets
are present, regardless of the chart's own kubernetesExport.enabled.

And when the configuration is not fully known the answer is "true", matching
what openvox-ca.tlsConfigured does with the same uncertainty: an unnecessary
projected token costs nothing, whereas a missing one makes the export or the
key provider fail while readiness still reports healthy.

That covers all four of configFullyKnown's inputs deliberately, not just
existingConfigMap — the fourth being a `--config` in `extraArgs`, which points
the server at a file the chart never rendered. Every one of them can carry the settings this decision turns
on, because they all outrank or replace the config file the chart renders:
`--openbao-auth-method=kubernetes` through `args`, and
PUPPET_CA_OPENBAO_AUTH_METHOD through a ConfigMap or Secret named in `envFrom`
(see docs/openbao-transit.md). The chart cannot read any of them.

It can read `env`, `extraEnv` and `extraArgs`, though, and each of those carries
the same setting — so all three are scanned here, the way
openvox-ca.tlsConfigured scans env/extraEnv for PUPPET_CA_TLS_CERT/KEY. Without
that, `config.ca_key_provider: openbao` plus any of
`env.PUPPET_CA_OPENBAO_AUTH_METHOD: kubernetes`, the same variable in
`extraEnv`, or `extraArgs: [--openbao-auth-method=kubernetes]` would leave the
config fully known, the merged config's openbao.auth_method empty, and the pod
without the projected token its key provider needs.

Each scan follows the server's own precedence: an empty value does not override
what the config file said (cmd/openvox-ca/config.go only assigns when the
variable is non-empty), and a value the chart cannot read counts as needing the
token, because that is the fail-open direction.
*/}}
{{- define "openvox-ca.needsAPIAccess" -}}
{{- if ne (include "openvox-ca.configFullyKnown" .) "true" -}}
true
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $authMethod := dig "openbao" "auth_method" "" $config -}}
{{- range $name, $value := .Values.env -}}
{{- if and (eq $name "PUPPET_CA_OPENBAO_AUTH_METHOD") $value }}{{ $authMethod = $value }}{{ end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if and (eq .name "PUPPET_CA_OPENBAO_AUTH_METHOD") .value }}{{ $authMethod = .value }}{{ end -}}
{{/*
  A valueFrom reference has no readable value, so its mere presence is the
  signal: the operator is feeding the auth method in from a Secret or ConfigMap
  and the chart cannot see which method it names.
*/}}
{{- if and (eq .name "PUPPET_CA_OPENBAO_AUTH_METHOD") (not .value) }}{{ $authMethod = "kubernetes" }}{{ end -}}
{{- end -}}
{{/*
  extraArgs is appended to the argument list the chart builds, so unlike `args`
  the chart can read it. `--openbao-auth-method=x` gives the method outright; the
  separated form leaves it in the next element, which is not worth reassembling
  — treat the bare flag as needing the token, again failing open.
*/}}
{{- range .Values.extraArgs -}}
{{- $arg := . | toString -}}
{{- if hasPrefix "--openbao-auth-method=" $arg }}{{ $authMethod = trimPrefix "--openbao-auth-method=" $arg }}{{ end -}}
{{- if eq $arg "--openbao-auth-method" }}{{ $authMethod = "kubernetes" }}{{ end -}}
{{- end -}}
{{- if eq (include "openvox-ca.exportConfigured" .) "true" -}}
true
{{- else if eq ($authMethod | toString) "kubernetes" -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Whether Kubernetes export is configured, by either route the server honours:
the chart's own flag, or targets set directly in config.

One definition, because this predicate is read by the token decision, the
reason the NOTES warning gives, and the RBAC gate, and an earlier pair of
copies had already drifted — the NOTE tested only kubernetesExport.enabled and
so gave no reason for a config-supplied export.

Note the config half is read even under existingConfigMap, where the chart
renders no config.yaml and those targets never reach the server. That is
deliberate for the token and the Role, which fail open, but it means a
config-derived export reason in the NOTE may name inert values —
exportTargetNames takes the stricter view and reports "unknown" there.
*/}}
{{- define "openvox-ca.exportConfigured" -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- if or .Values.kubernetesExport.enabled (dig "kubernetes_export" "targets" list $config) -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Whether the export Role and its bindings are rendered — export configured *and*
rbac.create.

One definition because three places need it and they have twice drifted apart:
rbac.yaml renders on it, the default-ServiceAccount refusal guards it, and the
NOTES warning discloses the unnarrowed patch grant it produces. Moving rbac.yaml
onto exportConfigured while leaving the refusal on kubernetesExport.enabled
opened a privilege escalation; fixing the refusal while leaving the NOTES warning
behind then hid the residual over-grant on the same route. Both were the same
mistake: one side of a coupling moved.
*/}}
{{- define "openvox-ca.exportRBACRendered" -}}
{{- if and (eq (include "openvox-ca.exportConfigured" .) "true") .Values.kubernetesExport.rbac.create -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Why the pod needs the Kubernetes API, as an operator-facing phrase, or empty
when the chart cannot name a reason.

Exists so the NOTES warning names the same reason the token decision acted on
instead of re-deriving it: an earlier copy tested only
.Values.kubernetesExport.enabled, so an export configured through
config.kubernetes_export got no reason at all even though that is precisely
what had made needsAPIAccess true. Both now go through
openvox-ca.exportConfigured.

Export is reported whenever it is configured, including when the wider
configuration is unknown — kubernetesExport.enabled and config are readable
whatever existingConfigMap or args are doing, so suppressing a reason the chart
does have would be a step backwards. Empty means only that no reason is
visible, which is the honest answer when the token is being mounted because the
chart cannot see far enough to rule anything out.
*/}}
{{- define "openvox-ca.apiAccessReason" -}}
{{- if eq (include "openvox-ca.exportConfigured" .) "true" -}}
Kubernetes export
{{- else if eq (include "openvox-ca.configFullyKnown" .) "true" -}}
{{- if eq (include "openvox-ca.needsAPIAccess" .) "true" -}}
OpenBao Kubernetes auth
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
automountServiceAccountToken: honour an explicit value, otherwise mount the
token only when something actually needs it.
*/}}
{{- define "openvox-ca.automountServiceAccountToken" -}}
{{- if kindIs "bool" .Values.automountServiceAccountToken -}}
{{- .Values.automountServiceAccountToken -}}
{{- else -}}
{{- include "openvox-ca.needsAPIAccess" . -}}
{{- end -}}
{{- end -}}

{{/*
Which Service port a route or ingress forwards to, given a backendPort
selection ("https" or "metrics"). Two spellings because the two APIs differ: an
Ingress backend references the port by name, a Gateway API backendRef by
number. Centralised so the rule lives in one place instead of being re-derived
in ingress.yaml, httproute.yaml and tlsroute.yaml.

Call with (dict "backendPort" <value> "root" $).
*/}}
{{- define "openvox-ca.routeBackendName" -}}
{{- if eq .backendPort "metrics" -}}metrics{{- else -}}https{{- end -}}
{{- end -}}

{{- define "openvox-ca.routeBackendPort" -}}
{{- if eq .backendPort "metrics" -}}
{{- .root.Values.metrics.port -}}
{{- else -}}
{{- .root.Values.service.port | int -}}
{{- end -}}
{{- end -}}

{{/*
Whether the chart can see the server's whole configuration.

It cannot when the config file is somebody else's (existingConfigMap), when
argv has been replaced outright (args), or when settings arrive from a
ConfigMap or Secret the chart never reads (envFrom) — each of those layers
outranks or replaces what the chart renders. Where the answer is "no", the
chart says so rather than asserting: it neither refuses an install it cannot
judge nor claims to know which scheme the probes should use.

A --config in extraArgs counts too, and is the subtlest of the four. The
chart renders its own --config and appends extraArgs straight after it, so a
second one wins outright (it is a plain pflag StringVar) and the server reads
a file the chart never saw — while the ConfigMap it did render goes unread.
Both spellings are caught: --config=/path, and the bare --config whose value
sits in the following element.
*/}}
{{- define "openvox-ca.configFullyKnown" -}}
{{- $configOverridden := false -}}
{{- range .Values.extraArgs -}}
{{- $arg := . | toString -}}
{{- if or (eq $arg "--config") (hasPrefix "--config=" $arg) }}{{ $configOverridden = true }}{{ end -}}
{{- end -}}
{{- if or .Values.existingConfigMap .Values.args .Values.envFrom $configOverridden -}}
false
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
Whether the server will serve HTTPS.

It does so exactly when a certificate and a key are both configured — on any
layer. The config file is the one the chart renders; environment variables
outrank it, so PUPPET_CA_TLS_CERT/KEY set through env or extraEnv count too,
and are how someone feeds the certificate paths in from a Secret.

When the configuration is not fully known this answers "true": HTTPS is the
normal case, and it is the answer that neither blocks a correct install nor
makes the probes fail on one.
*/}}
{{- define "openvox-ca.tlsConfigured" -}}
{{- if ne (include "openvox-ca.configFullyKnown" .) "true" -}}
true
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $cert := dig "tls_cert" "" $config -}}
{{- $key := dig "tls_key" "" $config -}}
{{- range $name, $value := .Values.env -}}
{{- if eq $name "PUPPET_CA_TLS_CERT" }}{{ $cert = $value }}{{ end -}}
{{- if eq $name "PUPPET_CA_TLS_KEY" }}{{ $key = $value }}{{ end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if eq .name "PUPPET_CA_TLS_CERT" }}{{ $cert = "set" }}{{ end -}}
{{- if eq .name "PUPPET_CA_TLS_KEY" }}{{ $key = "set" }}{{ end -}}
{{- end -}}
{{- if and $cert $key -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Scheme for the HTTP probes. The kubelet has to speak whatever the server
speaks, and without TLS the server serves cleartext.
*/}}
{{- define "openvox-ca.probeScheme" -}}
{{- if eq (include "openvox-ca.tlsConfigured" .) "true" -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}

{{/*
One probe, with the scheme filled in when the operator has not chosen one. The
"enabled" key is a chart concept and never belongs in the emitted spec.
*/}}
{{- define "openvox-ca.probe" -}}
{{- $probe := omit .probe "enabled" -}}
{{- if and $probe.httpGet (not $probe.httpGet.scheme) -}}
{{- $httpGet := merge (dict "scheme" (include "openvox-ca.probeScheme" .root)) (deepCopy $probe.httpGet) -}}
{{- $probe = merge (dict "httpGet" $httpGet) (omit $probe "httpGet") -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end -}}

{{/*
Preconditions, checked once from the Deployment so that every one of them
fails at `helm install` time with an explanation, rather than at runtime with a
CrashLoopBackOff or a Service that silently routes nowhere.
*/}}
{{- define "openvox-ca.validate" -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}

{{/*
  Three settings decide one thing each in two places: the convenience value
  shapes the Kubernetes object, and the merged config tells the server. `config`
  wins by contract, so overriding one of these there moves the server and leaves
  the Service, the container port or the volume mount behind — and two of the
  three fail silently. A wrong `port` never becomes ready; a wrong
  `metrics_listen` leaves the Service and any ServiceMonitor scraping a port
  nothing listens on while readiness stays green; a wrong `cadir` points the CA
  at a path outside its volume, which readOnlyRootFilesystem then makes
  unwritable.

  Only checked when the chart can read the whole configuration, and only when
  the two disagree — the convenience values are what the chart writes into
  config in the first place, so they agree unless someone overrode one.
*/}}
{{- if eq (include "openvox-ca.configFullyKnown" .) "true" -}}
{{- $cfgPort := dig "port" (.Values.listen.port | int) $config | int -}}
{{- if ne $cfgPort (.Values.listen.port | int) -}}
{{- fail (printf "config.port is %d but listen.port is %d, and listen.port is what the container port, the Service and the probes use — so the server would listen where nothing reaches it and the pod would never become ready. Set listen.port to %d as well, or drop the config override." $cfgPort (.Values.listen.port | int) $cfgPort) -}}
{{- end -}}
{{- $cfgCadir := dig "cadir" "" $config -}}
{{- if and .Values.persistence.enabled $cfgCadir (ne $cfgCadir .Values.persistence.mountPath) -}}
{{- fail (printf "config.cadir is %q but the PersistentVolumeClaim is mounted at %q, so the CA would write outside its volume — and the root filesystem is read-only by default, so it could not write at all. Set persistence.mountPath to %q as well, or drop the config override." $cfgCadir .Values.persistence.mountPath $cfgCadir) -}}
{{- end -}}
{{- if .Values.metrics.enabled -}}
{{- $listen := dig "metrics_listen" "" $config -}}
{{- if $listen -}}
{{- $parts := splitList ":" $listen -}}
{{- $cfgMetricsPort := last $parts | int -}}
{{- if and $cfgMetricsPort (ne $cfgMetricsPort (.Values.metrics.port | int)) -}}
{{- fail (printf "config.metrics_listen is %q but metrics.port is %d, and metrics.port is what the container port, the Service and any ServiceMonitor use — so they would scrape a port nothing listens on, silently, while readiness stayed green. Set metrics.port to %d as well, or drop the config override." $listen (.Values.metrics.port | int) $cfgMetricsPort) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  The server refuses to serve plain HTTP on a non-loopback address, because an
  on-path host could then inject forged certificates. Reproduce its condition
  so the operator is told at install time, with the same remedies, instead of
  watching the pod crash-loop.

  Only checked when the chart can see the whole configuration: a guard that
  fires on a configuration it cannot read is worse than no guard at all.

  The loopback forms are exactly the ones that work end to end. The server
  tests net.ParseIP(host).IsLoopback() or host == "localhost"
  (cmd/openvox-ca/main.go), which rejects the bracketed "[::1]"; and it builds
  its listen address as host + ":" + port, which turns a bare "::1" into the
  unparseable "::1:8140". That leaves 127.0.0.0/8 and localhost. Note that
  "[::]" — the chart's documented dual-stack spelling — is not loopback and
  correctly does not qualify.
*/}}
{{- if eq (include "openvox-ca.configFullyKnown" .) "true" -}}
{{- $host := dig "host" "" $config | toString -}}
{{- $loopback := or (hasPrefix "127." $host) (eq $host "localhost") -}}
{{- if and (ne (include "openvox-ca.tlsConfigured" .) "true") (not (dig "no_tls_required" false $config)) (not $loopback) -}}
{{- fail (printf "openvox-ca will refuse to start: no server TLS certificate is configured and the listen address (%s) is not loopback, which the server rejects as vulnerable to certificate injection.\n\nSet one of:\n  tls.existingSecret       a kubernetes.io/tls Secret holding the server certificate (recommended; Puppet agents require HTTPS)\n  config.tls_cert/tls_key  paths to a certificate you mount yourself\n  env/extraEnv             PUPPET_CA_TLS_CERT and PUPPET_CA_TLS_KEY, to feed those paths in from a Secret\n  config.no_tls_required   true, only behind a trusted TLS proxy that re-originates TLS\n  listen.host              127.0.0.1 or localhost, for a sidecar-only deployment" $host) -}}
{{- end -}}
{{- end -}}

{{/*
  A route pointed at the metrics port when the exporter is off installs
  cleanly and then routes to a Service port that was never created.
*/}}
{{- if not .Values.metrics.enabled -}}
{{- range $name, $route := dict "ingress" .Values.ingress "gateway.tlsRoute" .Values.gateway.tlsRoute "gateway.httpRoute" .Values.gateway.httpRoute -}}
{{- if and $route.enabled (eq $route.backendPort "metrics") -}}
{{- fail (printf "%s.backendPort is \"metrics\", but metrics.enabled is false, so the Service has no metrics port to route to. Set metrics.enabled: true, or point it at \"https\"." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Binding the export Role to the namespace's default ServiceAccount would
  hand create/patch on every Secret in the namespace to every pod in it.
*/}}
{{- if eq (include "openvox-ca.exportRBACRendered" .) "true" -}}
{{- if eq (include "openvox-ca.serviceAccountName" .) "default" -}}
{{- fail "kubernetesExport.rbac.create would bind the export Role to the namespace's default ServiceAccount, granting create/patch on Secrets to every pod in the namespace. Set serviceAccount.create: true, or serviceAccount.name to a dedicated account." -}}
{{- end -}}
{{- end -}}

{{/*
  extraConfigFiles is emitted into the same ConfigMap `data` map as the files the
  chart renders, and it is ranged last, so a colliding key produces two entries
  of one name and the operator's wins. Then every decision the chart made — the
  TLS precondition, the probe scheme, the token, export RBAC — was computed from
  a config.yaml the pod never reads, which is the failure existingConfigMap and a
  --config in extraArgs are both treated as unknown to avoid. For puppet-server
  the substituted file is the mTLS admin allow list, and it escapes the
  entry-by-entry validation applied to puppetServers below.

  The set is derived from what configMapData will actually emit, not hardcoded:
  puppet-server and autosign.conf are conditional, and existingConfigMap renders
  no ConfigMap at all, so a fixed list refused working configurations —
  puppetServers left empty with the allow list supplied by hand, say — and
  pushed the operator toward existingConfigMap, which is a worse posture (no
  config checksum, and the export grant widens to unnarrowed patch).

  The shape is checked first, and that is the load-bearing half. Comparing the
  key against a name set is comparing a Go string to something that gets
  interpolated raw into YAML, so equality here is not YAML's equality: a padded
  key parses back to the trimmed name, a key wrapped in quotes parses to the
  unquoted name, and a key containing a newline injects a whole extra entry
  because the block is re-indented. Two attempts at enumerating those spellings
  were both bypassed. So the key must look like a ConfigMap key, and it is quoted
  where it is emitted, so a hostile key cannot contribute YAML structure even if
  this guard is edited badly later.

  The rule is Kubernetes' own IsConfigMapKey: the character set, a 253-character
  cap, and three exclusions a bare character class misses — ".", ".." and any
  name beginning "..". Those pass a character-class check and render a manifest
  the API server then refuses.
*/}}
{{- $rendered := dict -}}
{{- if not .Values.existingConfigMap -}}
{{- $_ := set $rendered "config.yaml" true -}}
{{- if .Values.puppetServers -}}{{- $_ := set $rendered "puppet-server" true -}}{{- end -}}
{{- if .Values.autosign.patterns -}}{{- $_ := set $rendered "autosign.conf" true -}}{{- end -}}
{{- end -}}
{{- range $name, $body := .Values.extraConfigFiles -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]{1,253}$" $name)) (eq $name ".") (eq $name "..") (hasPrefix ".." $name) -}}
{{- fail (printf "extraConfigFiles key %q is not a valid ConfigMap key: at most 253 of letters, digits, '-', '_' and '.', and not '.', '..' or a name beginning '..'. Whitespace, quotes and newlines are refused outright because YAML folds such a key onto a different one, which is how a name that looked distinct came to replace a file the chart renders." $name) -}}
{{- end -}}
{{- if hasKey $rendered $name -}}
{{- fail (printf "extraConfigFiles key %q is one the chart renders into the same ConfigMap, and yours would silently take its place. Use existingConfigMap for a config.yaml of your own, puppetServers for the admin allow list, or autosign.patterns for autosign.conf." $name) -}}
{{- end -}}
{{- end -}}

{{/*
  A ServiceMonitor for an exporter that is switched off scrapes nothing.
*/}}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) -}}
{{- fail "metrics.serviceMonitor.enabled requires metrics.enabled: the exporter is off, so there is nothing to scrape." -}}
{{- end -}}

{{/*
  An autoscaler with no metric configured does not autoscale: it pins the
  replica count at minReplicas and reports healthy while doing it.
*/}}
{{- if .Values.autoscaling.enabled -}}
{{- if not (or .Values.autoscaling.targetCPUUtilizationPercentage .Values.autoscaling.targetMemoryUtilizationPercentage .Values.autoscaling.metrics) -}}
{{- fail "autoscaling.enabled is set but no metric is configured, so the HorizontalPodAutoscaler would hold the replica count at minReplicas rather than scale. Set autoscaling.targetCPUUtilizationPercentage, targetMemoryUtilizationPercentage, or metrics." -}}
{{- end -}}
{{- end -}}

{{/*
  puppetServers and autosign.patterns are written one per line into the config
  ConfigMap. An entry containing a newline would end that block scalar early
  and inject a key of its own — and these two lists are the mTLS admin
  allow list and the autosign allow list, so a mangled one fails open.
*/}}
{{- range $list := list .Values.puppetServers .Values.autosign.patterns -}}
{{- range $entry := $list -}}
{{- if or (contains "\n" ($entry | toString)) (not (trim ($entry | toString))) -}}
{{- fail (printf "puppetServers and autosign.patterns entries must each be a single non-empty line; got %q" $entry) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The names the exporter will apply to, gathered from the merged config so that
targets supplied through config.kubernetes_export count too.

Returns the literal string "unknown" — distinct from an empty list — when the
export config is not the chart's to read, because the two mean opposite things
to the caller: "no targets, so grant nothing" versus "unknown targets, so grant
everything". A marker rather than a JSON null because Helm's fromJson rejects
anything that is not an object, so the caller has to test before decoding
anyway.
*/}}
{{- define "openvox-ca.exportTargetNames" -}}
{{- /*
  Keyed on configFullyKnown, not existingConfigMap alone. All four of its inputs
  mean the same thing here — the chart cannot read the export config — but only
  existingConfigMap was tested, so `args`, `envFrom` and a --config in extraArgs
  produced a create-only Role with no patch rule and no NOTES disclosure. If the
  real config carries kubernetes_export.targets, the exporter is refused on its
  first patch of an existing object while readiness stays green, which is the
  failure this file's header says it fixed. needsAPIAccess already routes through
  configFullyKnown for exactly this reason.
*/ -}}
{{- if ne (include "openvox-ca.configFullyKnown" .) "true" -}}
unknown
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $names := list -}}
{{- range (dig "kubernetes_export" "targets" list $config) -}}
{{- with (dig "metadata" "name" "" .) -}}
{{- $names = append $names . -}}
{{- end -}}
{{- end -}}
{{- $names | uniq | sortAlpha | toJson -}}
{{- end -}}
{{- end -}}

{{/*
The post-install notes.

Held in a named template rather than inline in NOTES.txt so that they can be
rendered — and therefore asserted — offline. `helm template` does not evaluate
NOTES.txt at all, and `helm install --dry-run` reaches for a cluster on Helm 3,
so a probe template that includes this is the only portable way to test the
warnings. They were the operator-facing half of a defect once already.
*/}}
{{- define "openvox-ca.notes" -}}
{{- $fullName := include "openvox-ca.fullname" . -}}
{{- $namespace := include "openvox-ca.namespace" . -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $backend := dig "storage_backend" "filesystem" $config -}}
{{- $tls := eq (include "openvox-ca.tlsConfigured" .) "true" -}}
{{- $replicas := ternary (int .Values.autoscaling.minReplicas) (int .Values.replicaCount) .Values.autoscaling.enabled -}}
{{- $autosign := dig "autosign_config" "" $config | toString -}}
openvox-ca {{ .Chart.AppVersion }} has been deployed as {{ $fullName }} in namespace {{ $namespace }}.

Image:           {{ include "openvox-ca.image" . }}
Storage backend: {{ $backend }}
Service:         {{ $fullName }}.{{ $namespace }}.svc:{{ .Values.service.port }}

Watch it come up:

  kubectl --namespace {{ $namespace }} rollout status deployment/{{ $fullName }}

Fetch the CA certificate once it is ready:

  kubectl --namespace {{ $namespace }} port-forward svc/{{ $fullName }} 8140:{{ .Values.service.port }}
  curl {{ if $tls }}-k https{{ else }}http{{ end }}://localhost:8140/puppet-ca/v1/certificate/ca

{{- if not $tls }}

WARNING: no server TLS certificate is configured, so openvox-ca is serving
plain HTTP. Puppet agents require HTTPS, and every endpoint authenticated by
client certificate — signing, revoking, listing — is unavailable. This is only
safe behind a proxy that terminates TLS and re-originates it to the pod. Set
tls.existingSecret to a kubernetes.io/tls Secret to serve TLS directly.
{{- end }}
{{- if and (has $backend (list "filesystem" "sqlite")) (not .Values.persistence.enabled) }}

WARNING: the {{ $backend }} backend keeps the entire CA — including its private
key — in {{ .Values.persistence.mountPath }}, but persistence is disabled, so
that directory is an emptyDir. The CA will be regenerated from scratch on every
restart and previously issued certificates will stop verifying. Set
persistence.enabled: true, or switch to an external storage backend.
{{- end }}
{{- if and (has $backend (list "filesystem" "sqlite")) (gt $replicas 1) }}

WARNING: {{ if .Values.autoscaling.enabled }}autoscaling starts at {{ $replicas }} replicas{{ else }}replicaCount is {{ $replicas }}{{ end }}, but the
{{ $backend }} backend is not safe to share between replicas. Use postgres,
mysql, etcd, or redis to run more than one — see
https://github.com/voxpupuli/openvox-ca/blob/main/docs/storage-backends.md
{{- end }}
{{- if eq $autosign "true" }}

WARNING: autosigning is set to "true", so every CSR that reaches the CA is
signed without review. Anyone who can reach the API can obtain a valid
certificate for any name. Use this in development only.
{{- end }}
{{- if .Values.gateway.httpRoute.enabled }}

WARNING: gateway.httpRoute is enabled. An HTTPRoute makes the Gateway terminate
TLS, so openvox-ca never sees an agent's client certificate and every endpoint
authenticated by one — signing, revoking, listing — stops authenticating. Use
gateway.tlsRoute for agent traffic, which passes the connection through intact,
and keep the HTTPRoute for the anonymous endpoints (CRL, OCSP, health) only.
{{- end }}
{{- if and (eq (include "openvox-ca.exportRBACRendered" .) "true") (eq (include "openvox-ca.exportTargetNames" .) "unknown") }}

WARNING: Kubernetes export RBAC was created with {{ if eq .Values.kubernetesExport.rbac.scope "ClusterRole" }}cluster-wide{{ else }}namespace-wide{{ end }} patch on every
Secret and ConfigMap in scope. The export targets live in a ConfigMap the chart
does not render (existingConfigMap), so it cannot narrow the grant to their
names. To restrict it, move the targets into kubernetesExport.targets, or drop
kubernetesExport.rbac.create and manage the Role yourself with an explicit
resourceNames list.
{{- end }}
{{- if and .Values.metrics.enabled (not .Values.networkPolicy.enabled) }}

NOTE: the Prometheus exporter is enabled on port {{ .Values.metrics.port }}. Its
leaf-certificate series carry node hostnames as label values, and no
NetworkPolicy is in place to restrict who can scrape it. Consider
networkPolicy.enabled: true.
{{- end }}
{{- if and .Values.networkPolicy.enabled .Values.networkPolicy.egress.enabled (eq (include "openvox-ca.needsAPIAccess" .) "true") }}

NOTE: this pod may talk to the Kubernetes API{{ with (include "openvox-ca.apiAccessReason" .) }} ({{ . }}){{ end }}, but
egress is restricted and the chart cannot know your API server's address. If it
does, add a rule for it to networkPolicy.egress.rules, or the feature will fail
while readiness still reports healthy.
{{- end }}
{{- if not (or .Values.puppetServers (dig "puppet_server" "" $config) (dig "puppet_server_file" "" $config)) }}

NOTE: no puppetServers are listed, so no CN is granted admin API access over
mTLS. Your OpenVox/Puppet Server compilers need to be listed here (or via
config.puppet_server) before they can sign, revoke, or list certificates.
{{- end }}

Full configuration reference: https://github.com/voxpupuli/openvox-ca/blob/main/docs/configuration.md
Chart documentation:          https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md
{{- end -}}
