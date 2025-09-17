def call(Map cfg = [:]) { runWithCatch('Snyk scan image') {
  String out = cfg.output ?: 'report/snyk-image.json'
  String dockerfile = cfg.dockerfile ?: 'Dockerfile'
  withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        mkdir -p report
        dockerImageName=\$( ${libraryResource 'utils/awk-extract-image.awk'} ${dockerfile} )
        snyk container test --severity-threshold=high --json-file-output=${out} \${dockerImageName}
      """
    }
  }
}
