def call(Map cfg = [:]) {
    String out = cfg.output ?: 'report/gitleaks-report.json'
    sh """
      gitleaks detect --source . --redact \\
      --report-format json \\
      --gitleaks-ignore-path . \\
      --report-path ${out}
    """
}
