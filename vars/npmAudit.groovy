import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('NPM Dependency Audit') {
    String out = cfg.output ?: 'report/npm-audit-report.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    sh """
      npm audit --audit-level=high --json > ${ShellUtils.shellQuote(out)}
    """
  }
}
