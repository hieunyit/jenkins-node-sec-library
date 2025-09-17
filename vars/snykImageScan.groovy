import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Snyk scan image') {
    String out = cfg.output ?: 'report/snyk-image.json'
    String dockerfile = cfg.dockerfile ?: 'Dockerfile'
    String awkFile = '.jenkins-awk-extract-image.awk'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')

    try {
      withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
        sh """
          dockerImageName=\$(awk -f ${ShellUtils.shellQuote(awkFile)} ${ShellUtils.shellQuote(dockerfile)})
          snyk container test --severity-threshold=high --json-file-output=${ShellUtils.shellQuote(out)} "\${dockerImageName}"
        """
      }
    } finally {
      sh "rm -f ${ShellUtils.shellQuote(awkFile)}"
    }
  }
}
