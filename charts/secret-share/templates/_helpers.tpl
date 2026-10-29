{{- define "secret-share.labels" -}}
app.kubernetes.io/name: secret-share
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "secret-share.selectorLabels" -}}
app.kubernetes.io/name: secret-share
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
