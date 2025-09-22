def call(String output = null) {
  String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/retire-report.json"
  sh """
    mkdir -p "\$(dirname '${outFile}')"
    retire --severity high --path . --outputformat json --outputpath '${outFile}'
  """
}
