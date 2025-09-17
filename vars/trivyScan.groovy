import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Trivy scan') {
    String out = cfg.output ?: 'report/trivy-report.json'
    String dockerfile = cfg.dockerfile ?: 'Dockerfile'
    String awkFile = '.jenkins-awk-extract-image.awk'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')

    try {
      sh """
        dockerImageName=\$(awk -f ${ShellUtils.shellQuote(awkFile)} ${ShellUtils.shellQuote(dockerfile)})
        trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress --quiet -f json -o ${ShellUtils.shellQuote(out)} "\${dockerImageName}"
      """
    } finally {
      sh "rm -f ${ShellUtils.shellQuote(awkFile)}"
    }
  }
}
