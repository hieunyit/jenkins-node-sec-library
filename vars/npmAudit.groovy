def call(Object arg = null) {
  String out
   String out
  if (arg instanceof CharSequence) {
    out = (arg as String)?.trim()
  } else if (arg instanceof Map) {
    out = (arg.output as String)?.trim()
  }
  if (!out) {
    String base = (env.REPORT_DIR ?: 'report').trim()
    out = "${base}/npm-audit-report.json"
  }
  
  sh "npm audit --audit-level=high --json > ${out}"
}
