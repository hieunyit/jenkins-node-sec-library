def call(Map cfg = [:]) { runWithCatch('Snyk Scan Source code') {
  String out = cfg.output ?: 'report/snyk-code.json'
    withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        mkdir -p report
        snyk code test --severity-threshold=high --json-file-output=${out}
      """
    }
  }
}
