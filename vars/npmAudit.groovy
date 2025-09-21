def call(String output = null) {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/npm-audit-report.json"
    sh "npm audit --audit-level=critical --json > ${outFile}"
}
