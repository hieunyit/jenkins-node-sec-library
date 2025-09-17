def call(Object arg = null) {
    String out
    if (arg instanceof CharSequence) {
      out = arg.toString().trim()
    } else if (arg instanceof Map) {
      out = (arg.output as String)?.trim()
    }
    if (!out) {
      String base = (env.REPORT_DIR ?: 'report').trim()
      out = "${base}/npm-audit-report.json"
    }
    def parentDir = { String p ->
      int i = (p ?: '').lastIndexOf('/')
      i > 0 ? p.substring(0, i) : ''
    }
    String dir = parentDir(out)
    if (dir) {
      sh "mkdir -p ${shQ(dir)}"
    }

    sh "npm audit --audit-level=high --json > ${shQ(out)}"
  }
}
