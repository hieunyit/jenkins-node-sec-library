import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Snyk Scan Source code') {
    String out = cfg.output ?: 'report/snyk-code.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    withCredentials([string(credentialsId: cfg.tokenCredId ?: 'snyk', variable: 'SNYK_TOKEN')]) {
      sh """
        snyk code test --severity-threshold=high --json-file-output=${ShellUtils.shellQuote(out)}
      """
    }
  }
}
