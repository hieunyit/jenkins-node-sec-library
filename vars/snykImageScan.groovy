def call(Map cfg = [:]) { runWithCatch('Snyk scan image') {
  String out = cfg.output ?: 'report/snyk-image.json'
  String dockerfile = cfg.dockerfile ?: 'Dockerfile'
  String awkFile = '.jenkins-awk-extract-image.awk'
  writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
  withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        mkdir -p report
        dockerImageName=\$(awk -f ${awkFile} ${dockerfile})
        snyk container test --severity-threshold=high --json-file-output=${out} \${dockerImageName}
      """
    }
  }
}
