import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Snyk Scan SCA') {
    String out = cfg.output ?: 'report/snyk-sca.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        snyk test --severity-threshold=high --json-file-output=${ShellUtils.shellQuote(out)}
      """
    }
  }
}
