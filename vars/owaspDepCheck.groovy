def call(String output = null) {
  String reportDir = output ?: "${env.REPORT_DIR ?: 'report'}"
  String installation = 'OWASP-DepCheck-12'
  sh "mkdir -p ${reportDir}"
  dependencyCheck(
    additionalArguments: "--scan ./ --out ./${reportDir} --format ALL --exclude '**/test/files/**' --disableArchive --prettyPrint",
    odcInstallation: installation
  )
}
