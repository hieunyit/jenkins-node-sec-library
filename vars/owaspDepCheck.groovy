def call(Map cfg = [:]) { runWithCatch('retire.js scan Dependency') {
  String out = cfg.output ?: 'report/retire-report.json'
    sh """
      mkdir -p report
      retire --severity high --path . --outputformat json --outputpath ${out}
    """
  }
}
