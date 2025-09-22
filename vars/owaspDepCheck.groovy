def call(String owaspInstallation = null) {
  // Validate OWASP installation parameter
  if (!owaspInstallation) {
    error """
owaspInstallation parameter is required for OWASP Dependency Check.
Please provide the OWASP Dependency Check tool installation name configured in Jenkins.
Example: owaspInstallation('OWASP-DepCheck-12')
"""
  }
  
  
  // Create report directory
  sh "mkdir -p report"
  
  try {
    dependencyCheck(
      additionalArguments: "--scan ./ --out ./report --format ALL --exclude '**/test/files/**' --disableArchive --prettyPrint",
      odcInstallation: owaspInstallation
    )
    echo "OWASP Dependency Check completed successfully using installation: ${owaspInstallation}"
    echo "Reports saved to: report"
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
