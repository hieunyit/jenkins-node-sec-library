def call(Map cfg = [:]) { runWithCatch('Snyk Scan SCA') {
  String out = cfg.output ?: 'report/snyk-sca.json'
    withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        mkdir -p report
        snyk test --severity-threshold=high --json-file-output=${out}
      """
    }
  } 
}
