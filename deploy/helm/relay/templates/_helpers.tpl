{{- define "relay.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "relay.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "relay.labels" -}}
{{ include "relay.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "relay.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "relay.config" -}}
{{- $c := .Values.config -}}
{{- if not $c.egress.allow }}{{ fail "config.egress.allow must list at least one prefix" }}{{ end -}}
{{- $cfg := dict
  "listen" ":8443"
  "issuer" (required "config.issuer is required" $c.issuer)
  "tls" (dict "dir" "/etc/relay/tls" "cert" "tls.crt" "key" "tls.key" "reload_interval" .Values.tls.reloadInterval)
  "registration" (dict "dir" "/var/lib/relay/registration")
  "egress" (dict "allow" $c.egress.allow "exceptions" ($c.egress.exceptions | default list))
  "session" $c.session
  "limits" $c.limits
  "shutdown_timeout" $c.shutdownTimeout
  "log_level" $c.logLevel
-}}
{{- if .Values.issuerCA.configMapName }}{{ $_ := set $cfg "issuer_ca_file" (printf "/etc/relay/issuer-ca/%s" .Values.issuerCA.key) }}{{ end -}}
{{- if kindIs "map" $c.dpopNonces }}
{{- $nonces := deepCopy $c.dpopNonces }}
{{- if .Values.nonceKey.secretName }}{{ $_ := set $nonces "key_file" (printf "/etc/relay/nonce-key/%s" .Values.nonceKey.key) }}
{{- else if gt (int .Values.replicaCount) 1 }}{{ fail "config.dpopNonces with more than one replica needs nonceKey.secretName" }}{{ end }}
{{- $_ := set $cfg "dpop_nonces" $nonces }}
{{- end -}}
{{- toPrettyJson $cfg -}}
{{- end -}}
