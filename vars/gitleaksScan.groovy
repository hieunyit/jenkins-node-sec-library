def call(String output = null) {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/gitleaks-report.json"
    sh """
        mkdir -p "\$(dirname '${outFile}')"
        gitleaks detect --source . --redact \\
          --report-format json \\
          --gitleaks-ignore-path . \\
          --report-path '${outFile}'
    """
}
