{{- define "ccc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ccc.fullname" -}}
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

{{- define "ccc.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "ccc.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "ccc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ccc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* DNS_OVERRIDES string from the dnsOverrides map, sorted for stable checksums. */}}
{{- define "ccc.dnsOverrides" -}}
{{- $parts := list }}
{{- range $host := keys .Values.dnsOverrides | sortAlpha }}
{{- $parts = append $parts (printf "%s=%s" $host (join "," (index $.Values.dnsOverrides $host))) }}
{{- end }}
{{- join ";" $parts }}
{{- end }}

{{- define "ccc.theme" -}}
{{- $parts := list }}
{{- range $k := keys (omit .Values.theme "dark") | sortAlpha }}
{{- $parts = append $parts (printf "%s=%s" $k (index $.Values.theme $k)) }}
{{- end }}
{{- with .Values.theme.dark }}
{{- range $k := keys . | sortAlpha }}
{{- $parts = append $parts (printf "dark.%s=%s" $k (index $.Values.theme.dark $k)) }}
{{- end }}
{{- end }}
{{- join ";" $parts }}
{{- end }}
