{{/*
Expand the name of the chart.
*/}}
{{- define "trivy-admission-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "trivy-admission-controller.fullname" -}}
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
{{- define "trivy-admission-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "trivy-admission-controller.labels" -}}
helm.sh/chart: {{ include "trivy-admission-controller.chart" . }}
{{ include "trivy-admission-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "trivy-admission-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-admission-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "trivy-admission-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "trivy-admission-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the webhook to use
*/}}
{{- define "trivy-admission-controller.webhookName" -}}
{{- default "trivy.admissioncontroller.com" .Values.webhook.name }}
{{- end }}

{{/*
Define webhook fail policy
*/}}
{{- define "trivy-admission-controller.failurePolicy" -}}
{{- default "Fail" .Values.config.failPolicy }}
{{- end }}

{{/*
Generate certificates for the admission controller
*/}}
{{- define "trivy-admission-controller.tlsGenCerts" -}}
    {{- $secret := lookup "v1" "Secret" .Release.Namespace (include "trivy-admission-controller.tlsCertsSecretName" .) -}}
    {{- if $secret -}}
        {{- printf "%s$%s$%s" (index $secret.data "tls.crt") (index $secret.data "tls.key") (index $secret.data "ca.crt") -}}
    {{- else -}}
        {{- $svcName := include "trivy-admission-controller.fullname" . -}}
        {{- $dnsNames := list -}}
        {{- $dnsNames = append $dnsNames "localhost" -}}
        {{- $dnsNames = append $dnsNames $svcName -}}
        {{- $dnsNames = append $dnsNames (printf "%s.%s.svc" $svcName .Release.Namespace) -}}
        {{- $dnsNames = append $dnsNames (printf "%s.%s.svc.cluster.local" $svcName .Release.Namespace) -}}

        {{- $ca := genCA (include "trivy-admission-controller.fullname" .) 3650 -}}
        {{- $tlsCert := genSignedCert (include "trivy-admission-controller.fullname" .) (list "127.0.0.1") $dnsNames 3650 $ca -}}
        {{- printf "%s$%s$%s" ($tlsCert.Cert | b64enc) ($tlsCert.Key | b64enc) ($ca.Cert | b64enc) -}}
    {{- end -}}
{{- end -}}

{{/*
Audit Cert File
*/}}
{{- define "trivy-admission-controller.tlsCertFileName" -}}
tls.crt
{{- end }}


{{/*
Audit Cert Private Key File
*/}}
{{- define "trivy-admission-controller.tlsCertPrivateKeyFileName" -}}
tls.key
{{- end }}

{{/*
Path to mount TLS certificates inside the container
*/}}
{{- define "trivy-admission-controller.tlsMountPath" -}}
/etc/webhook/certs
{{- end }}

{{/*
Config file name
*/}}
{{- define "trivy-admission-controller.configFileName" -}}
config.yaml
{{- end }}

{{/*
Config file name
*/}}
{{- define "trivy-admission-controller.configMapName" -}}
{{ include "trivy-admission-controller.fullname" . }}-cm
{{- end }}

{{/*
Path to mount configmap inside the container
*/}}
{{- define "trivy-admission-controller.configMountPath" -}}
/etc/trivy-admission-controller/
{{- end }}

{{/*
CA Cert File Name
*/}}
{{- define "trivy-admission-controller.caCertFileName" -}}
ca.crt
{{- end }}

{{/*
TLS Secret Name
*/}}
{{- define "trivy-admission-controller.tlsCertsSecretName" -}}
    {{- include "trivy-admission-controller.secretName" . -}}-tls-certs
{{- end -}}

{{/*
TLS Secret Name
*/}}
{{- define "trivy-admission-controller.secretName" -}}
    {{- include "trivy-admission-controller.fullname" . -}}
{{- end -}}


