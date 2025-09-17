import org.jenkinsci.nodesec.ShellUtils

def call(Map cfg = [:]) {
  runWithCatch('retire.js scan Dependency') {
    String out = cfg.output ?: 'report/retire-report.json'

    String outputDir = ShellUtils.parentDir(out)
    if (outputDir) {
      sh "mkdir -p ${ShellUtils.shellQuote(outputDir)}"
    }

    sh """
      retire --severity high --path . --outputformat json --outputpath ${ShellUtils.shellQuote(out)}
    """
  }
}
