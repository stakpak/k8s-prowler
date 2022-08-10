{{- define "prowler-pod" -}}
serviceAccountName: {{ .Chart.Name }}
containers:
- name: {{ .Chart.Name }}
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  securityContext:
    capabilities:
      drop:
      - ALL
    runAsNonRoot: true
    runAsUser: 34000
  command: ["./entrypoint.sh"]
  args:
  - -r 
  - {{ required "prowler.region is required" .Values.prowler.region }}
  - -f 
  - {{ required "prowler.region is required" .Values.prowler.region }}
  {{- with .Values.prowler.groupCheck }}
  - -g 
  - {{ . }}
  {{- end }}
restartPolicy: OnFailure
{{- end }}