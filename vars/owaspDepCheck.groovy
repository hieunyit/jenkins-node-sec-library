def call(String output = null, String owaspInstallation = null) {
  String owaspInstallation = owaspInstallation ?: env.OWASP_INSTALLATION
  String reportDir = output ?: "${env.REPORT_DIR ?: 'report'}"
  if (!owaspInstallation) {
    error """
owaspInstallation parameter is required for OWASP Dependency Check.
Please provide the OWASP Dependency Check tool installation name configured in Jenkins.
Example: call(owaspInstallation: 'OWASP-DepCheck-v7')
"""
  }
  
  sh "mkdir -p ${reportDir}"
  
  try {
    dependencyCheck(
      additionalArguments: "--scan ./ --out ./${reportDir} --format ALL --exclude '**/test/files/**' --disableArchive --prettyPrint",
      odcInstallation: owaspInstallation
    )
    echo "OWASP Dependency Check completed successfully using installation: ${owaspInstallation}"
    echo "Reports saved to: ${reportDir}"
  } catch (Exception e) {
    if (e.getMessage().contains("No tool named") || e.getMessage().contains("not found")) {
      error """
OWASP Dependency Check installation '${owaspInstallation}' not found in Jenkins.
Please check the tool configuration in: Manage Jenkins > Global Tool Configuration > OWASP Dependency-Check
Make sure the installation name matches exactly: '${owaspInstallation}'
"""
    } else {
      error "OWASP Dependency Check failed: ${e.getMessage()}"
    }
  }
}
