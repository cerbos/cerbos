{{/*
Expand the name of the chart.
*/}}
{{- define "cerbos.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cerbos.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cerbos.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cerbos.labels" -}}
helm.sh/chart: {{ include "cerbos.chart" . }}
{{ include "cerbos.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cerbos.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cerbos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the secret used to read the TLS certificates from
*/}}
{{- define "cerbos.tlsSecretName" -}}
{{ coalesce .Values.cerbos.tlsSecretName .Values.certManager.certSpec.secretName "None" }}
{{- end }}

{{/*
Determine the scheme based on whether the TLS secret is defined or not
*/}}
{{- define "cerbos.httpScheme" -}}
{{- $tlsDisabled := (eq (include "cerbos.tlsSecretName" .) "None") -}}
{{- if $tlsDisabled -}}
http
{{- else -}}
https
{{- end -}}
{{- end }}

{{/*
Prometheus annotations
*/}}
{{- define "cerbos.promAnnotations" -}}
prometheus.io/scrape: "true"
prometheus.io/port: "{{ .Values.cerbos.httpPort }}"
prometheus.io/path: "/_cerbos/metrics"
prometheus.io/scheme: {{ include "cerbos.httpScheme" . }}
{{- end }}

{{/*
Generate pod annotations based on config
*/}}
{{- define "cerbos.podAnnotations" -}}
{{- $annotations := mustMergeOverwrite .Values.podAnnotations (dict "checksum/config" (include "cerbos.config" . | sha256sum)) -}}
{{- if .Values.cerbos.prometheusPodAnnotationsEnabled -}}
{{- $promAnnotations := (include "cerbos.promAnnotations" .)| fromYaml -}}
{{- $annotations = mustMergeOverwrite $annotations $promAnnotations -}}
{{- end -}}
annotations:
  {{- $annotations | toYaml | nindent 2 }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cerbos.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cerbos.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Default configuration if none is provided
*/}}
{{- define "cerbos.defaultConfig" -}}
storage:
  driver: "disk"
  disk:
    directory: /work
    watchForChanges: false
{{- end }}


{{/*
Configuration derived from values provided by the user
*/}}
{{- define "cerbos.derivedConfig" -}}
{{- $tlsDisabled := (eq (include "cerbos.tlsSecretName" .) "None") -}}
server:
  httpListenAddr: ":{{ .Values.cerbos.httpPort }}"
  grpcListenAddr: ":{{ .Values.cerbos.grpcPort }}"
  {{- if not $tlsDisabled }}
  tls:
    cert: /certs/tls.crt
    key: /certs/tls.key
    caCert: /certs/ca.crt
  {{- end }}
{{- end }}


{{/*
Merge the configurations to obtain the final configuration file
*/}}
{{- define "cerbos.config" -}}
{{- $defaultConf := (include "cerbos.defaultConfig" .) | fromYaml -}}
{{- $derivedConf := (include "cerbos.derivedConfig" .) | fromYaml -}}
{{ mustMergeOverwrite $defaultConf .Values.cerbos.config $derivedConf | toYaml }}
{{- end }}

{{/*
Detect if hub driver is used with default config
*/}}
{{- define "cerbos.defaultHubDriverEnabled" -}}
{{- $isBundleDriver := (eq (dig "config" "storage" "driver" "<not_defined>" .Values.cerbos) "bundle") -}}
{{- $isHubDriver := (eq (dig "config" "storage" "driver" "<not_defined>" .Values.cerbos) "hub") -}}
{{- $isBundleStorage := (or $isBundleDriver $isHubDriver) -}}
{{- $isDefaultTmp := (eq (dig "config" "storage" "bundle" "remote" "tempDir" "<not_defined>" .Values.cerbos) "<not_defined>") -}}
{{- $isDefaultCache := (eq (dig "config" "storage" "bundle" "remote" "cacheDir" "<not_defined>" .Values.cerbos) "<not_defined>") -}}
{{- if (and $isBundleStorage $isDefaultTmp $isDefaultCache) -}}yes{{- else -}}no{{- end -}}
{{- end }}

{{/*
The image reference to use in pods
*/}}
{{- define "cerbos.image" -}}
"{{ .Values.image.repository }}
{{- with .Values.image.digest -}}
@{{ . }}
{{- else -}}
:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
"
{{- end }}

{{/*
Topology spread constraints with label selector injected
*/}}
{{- define "cerbos.topologySpreadConstraints" -}}
{{- if .Values.topologySpreadConstraints }}
{{- $defaultLabels := (fromYaml (include "cerbos.selectorLabels" $)) }}
{{- $defaultLabelSelector := (dict "labelSelector" (dict "matchLabels" $defaultLabels)) }}
{{- $constraints := list }}
{{- range $c := .Values.topologySpreadConstraints }}
{{- if (hasKey $c "labelSelector") }}
{{- $constraints = (append $constraints $c) }}
{{- else }}
{{- $constraints = (append $constraints (mergeOverwrite $c $defaultLabelSelector)) }}
{{- end }}
{{- end }}
topologySpreadConstraints:
{{ toYaml $constraints | indent 2 }}
{{- end }}
{{- end }}
