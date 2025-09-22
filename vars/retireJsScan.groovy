def call(String output = null) {
  sh """
    mkdir -p report
    retire --severity high --path . --outputformat json --outputpath report/retire-report.json
  """
}
