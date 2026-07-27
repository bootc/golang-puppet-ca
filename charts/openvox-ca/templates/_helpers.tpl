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
Service port name a route or ingress should target.
*/}}
{{- define "openvox-ca.backendPortName" -}}
{{- $port := . -}}
{{- if eq $port "metrics" -}}metrics{{- else -}}https{{- end -}}
{{- end -}}
