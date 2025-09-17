import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('OPA Conftest') {
    String out = cfg.output ?: 'report/opa-report.sarif'
    String policyDir = cfg.policyDir ?: 'policy'
    String dockerfile = cfg.dockerfile ?: 'Dockerfile'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    sh """
      conftest test --parser dockerfile -p ${ShellUtils.shellQuote(policyDir)} ${ShellUtils.shellQuote(dockerfile)} --output sarif > ${ShellUtils.shellQuote(out)}
    """
  }
}
