def call(Map cfg = [:]) { runWithCatch('NPM Dependency Audit') {
  String out = cfg.output ?: 'report/npm-audit-report.json'
    sh """
      mkdir -p report
      npm audit --audit-level=high --json > ${out}
    """
  }
}
