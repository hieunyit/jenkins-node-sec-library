import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('Gitleaks scan secret') {
    String out = cfg.output ?: 'report/gitleaks-report.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    sh """
      gitleaks detect --source . --redact \\
      --report-format json \\
      --gitleaks-ignore-path . \\
      --report-path ${ShellUtils.shellQuote(out)}
    """
  }
}
