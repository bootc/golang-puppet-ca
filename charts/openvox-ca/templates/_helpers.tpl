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
{{ $name }}: |
{{ $body | trimSuffix "\n" | indent 2 }}
{{- end }}
{{- end -}}

{{/*
Whether the pod needs to talk to the Kubernetes API: for the export feature, or
for OpenBao's native Kubernetes auth (which reads the projected SA token).
*/}}
{{- define "openvox-ca.needsAPIAccess" -}}
{{- if .Values.kubernetesExport.enabled -}}
true
{{- else if eq (dig "openbao" "auth_method" "" .Values.config) "kubernetes" -}}
true
{{- else -}}
false
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
Whether the server will serve HTTPS: it does so exactly when both a certificate
and a key are configured, whether by the tls block or by config directly.

With existingConfigMap the chart cannot see the config at all, so it assumes
TLS is configured — the normal case, and the assumption that fails safe: the
alternative is warning and refusing to install on a configuration that is
perfectly correct. Operators terminating TLS elsewhere set the probe scheme
themselves.
*/}}
{{- define "openvox-ca.tlsConfigured" -}}
{{- if .Values.existingConfigMap -}}
true
{{- else -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- if and (dig "tls_cert" "" $config) (dig "tls_key" "" $config) -}}
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
  The server refuses to serve plain HTTP on a non-loopback address, because an
  on-path host could then inject forged certificates. Reproduce its three-way
  condition here so the operator is told at install time, with the same three
  remedies, instead of watching the pod crash-loop.
*/}}
{{- $host := dig "host" "" $config | toString -}}
{{- $loopback := or (hasPrefix "127." $host) (eq $host "::1") (eq $host "[::1]") (eq $host "localhost") -}}
{{- if and (ne (include "openvox-ca.tlsConfigured" .) "true") (not (dig "no_tls_required" false $config)) (not $loopback) -}}
{{- fail (printf "openvox-ca will refuse to start: no server TLS certificate is configured and the listen address (%s) is not loopback, which the server rejects as vulnerable to certificate injection.\n\nSet one of:\n  tls.existingSecret       a kubernetes.io/tls Secret holding the server certificate (recommended; Puppet agents require HTTPS)\n  config.tls_cert/tls_key  paths to a certificate you mount yourself\n  config.no_tls_required   true, only behind a trusted TLS proxy that re-originates TLS\n  listen.host              a loopback address, for a sidecar-only deployment" $host) -}}
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
{{- if and .Values.kubernetesExport.enabled .Values.kubernetesExport.rbac.create -}}
{{- if eq (include "openvox-ca.serviceAccountName" .) "default" -}}
{{- fail "kubernetesExport.rbac.create would bind the export Role to the namespace's default ServiceAccount, granting create/patch on Secrets to every pod in the namespace. Set serviceAccount.create: true, or serviceAccount.name to a dedicated account." -}}
{{- end -}}
{{- end -}}

{{/*
  A ServiceMonitor for an exporter that is switched off scrapes nothing.
*/}}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) -}}
{{- fail "metrics.serviceMonitor.enabled requires metrics.enabled: the exporter is off, so there is nothing to scrape." -}}
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
targets supplied through config.kubernetes_export count too. Empty when the
config is not the chart's to read, which is the signal not to restrict.
*/}}
{{- define "openvox-ca.exportTargetNames" -}}
{{- if not .Values.existingConfigMap -}}
{{- $config := include "openvox-ca.config" . | fromYaml -}}
{{- $names := list -}}
{{- range (dig "kubernetes_export" "targets" list $config) -}}
{{- with (dig "metadata" "name" "" .) -}}
{{- $names = append $names . -}}
{{- end -}}
{{- end -}}
{{- $names | uniq | sortAlpha | toJson -}}
{{- else -}}
[]
{{- end -}}
{{- end -}}
