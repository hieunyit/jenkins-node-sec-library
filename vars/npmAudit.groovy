def call() {
  sh """
    mkdir -p report
    npm audit --audit-level=critical --json > report/npm-audit-report.json
  """
}
