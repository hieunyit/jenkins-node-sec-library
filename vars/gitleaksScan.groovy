def call() {
    sh """
        mkdir -p report
        gitleaks detect --source . --redact \\
          --report-format json \\
          --gitleaks-ignore-path . \\
          --report-path report/gitleaks-report.json
    """
}
