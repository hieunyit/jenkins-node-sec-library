import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Semgrep scan') {
    String out = cfg.output ?: 'report/semgrep-report.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    sh """
      semgrep scan \\
      --config p/owasp-top-ten \\
      --config p/security-audit \\
      --config p/secrets \\
      --config p/javascript \\
      --metrics=off \\
      --exclude node_modules --exclude dist --exclude build --exclude coverage --exclude .git \\
      --timeout 10 \\
      --error \\
      --json --json-output=${ShellUtils.shellQuote(out)}
    """
  }
}
