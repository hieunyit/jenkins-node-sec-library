def call(Map cfg = [:]) { runWithCatch('Trivy scan') {
  String out = cfg.output ?: 'report/trivy-report.json'
  String dockerfile = cfg.dockerfile ?: 'Dockerfile'
    sh """
      mkdir -p report
      dockerImageName=\$( ${libraryResource 'utils/awk-extract-image.awk'} ${dockerfile} )
      trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress --quiet -f json -o ${out} \${dockerImageName}
    """
  }
}
