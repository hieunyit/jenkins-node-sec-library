def call(Map cfg = [:]) { runWithCatch('Trivy scan') {
  String out = cfg.output ?: 'report/trivy-report.json'
  String dockerfile = cfg.dockerfile ?: 'Dockerfile'
  String awkFile = '.jenkins-awk-extract-image.awk'
  writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
  sh """
      mkdir -p report
      dockerImageName=\$(awk -f ${awkFile} ${dockerfile})
      trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress --quiet -f json -o ${out} \${dockerImageName}
    """
  }
}
