{{/*
Expand the name of the chart.
*/}}
{{- define "craton-hsm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "craton-hsm.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "craton-hsm.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels (used in matchLabels — must be immutable)
*/}}
{{- define "craton-hsm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "craton-hsm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels applied to all resources
*/}}
{{- define "craton-hsm.labels" -}}
{{ include "craton-hsm.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Validate mTLS configuration.
Fails rendering if TLS is enabled but mTLS is not configured and not explicitly disabled.
*/}}
{{- define "craton-hsm.validateMtls" -}}
{{- if and .Values.tls.enabled (not .Values.tls.clientCaSecretName) (not .Values.tls.disableMtls) }}
{{- fail "SECURITY ERROR: TLS is enabled but mTLS is not configured. Either set tls.clientCaSecretName to a secret containing your client CA, or set tls.disableMtls=true to explicitly acknowledge the risk of running without client authentication." }}
{{- end }}
{{- end }}

{{/*
Validate replicas vs persistence.
ReadWriteOnce PVCs cannot be shared across pods, so replicas > 1 with
persistence enabled would cause mount failures.
*/}}
{{- define "craton-hsm.validateReplicas" -}}
{{- if and .Values.persistence.enabled (gt (int .Values.daemon.replicas) 1) }}
{{- fail "CONFIGURATION ERROR: persistence.enabled=true with daemon.replicas > 1 is invalid. ReadWriteOnce PVCs cannot be mounted by multiple pods. Either use replicas=1, disable persistence, or convert to a StatefulSet with per-replica PVCs." }}
{{- end }}
{{- end }}

{{/*
Validate TLS configuration.
Fails rendering if TLS is disabled without explicit acknowledgement.
*/}}
{{- define "craton-hsm.validateTls" -}}
{{- if and (not .Values.tls.enabled) (not .Values.tls.acceptInsecure) }}
{{- fail "SECURITY ERROR: TLS is disabled — gRPC traffic will be unencrypted. Set tls.enabled=true for production, or set tls.acceptInsecure=true to explicitly acknowledge plaintext gRPC (NOT recommended)." }}
{{- end }}
{{- end }}

{{/*
Validate audit configuration.
Fails rendering if persistence is disabled and audit disable is not explicitly acknowledged.
*/}}
{{- define "craton-hsm.validateAudit" -}}
{{- if and (not .Values.persistence.enabled) (not .Values.audit.acceptNoLogging) }}
{{- fail "SECURITY ERROR: Persistence is disabled, which means audit logs will be lost on restart. Either set persistence.enabled=true, or set audit.acceptNoLogging=true to explicitly acknowledge running without persistent audit trails." }}
{{- end }}
{{- end }}
