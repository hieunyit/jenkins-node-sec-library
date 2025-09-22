def call(String output = null) {
  String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/npm-audit-report.json"
  sh """
    mkdir -p "\$(dirname '${outFile}')"
    npm audit --audit-level=critical --json > ${outFile}
  """
}
