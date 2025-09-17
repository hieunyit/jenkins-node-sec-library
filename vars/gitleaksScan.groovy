def call(Object arg = null) {
  String out
  if (arg instanceof CharSequence) {
    out = (arg as String)?.trim()
  } else if (arg instanceof Map) {
    out = (arg.output as String)?.trim()
  }
  if (!out) {
    String base = (env.REPORT_DIR ?: 'report').trim()
    out = "${base}/gitleaks-report.json"
  }

  sh """
    mkdir -p "\$(dirname '${out}')"
    gitleaks detect --source . --redact \
      --report-format json \
      --gitleaks-ignore-path . \
      --report-path '${out}'
  """
}
