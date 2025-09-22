def call(String output = null, String snykTokenCredId = null) {
    if (!snykTokenCredId) {
        error """
snykTokenCredId parameter is required for Snyk SCA scan.
Please provide the Snyk token credential ID configured in Jenkins.
Example: call(snykTokenCredId: 'snyk-token')
"""
    }
    
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/snyk-sca.json"
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    try {
        withCredentials([string(credentialsId: snykTokenCredId, variable: 'SNYK_TOKEN')]) {
            sh "snyk test --severity-threshold=high --json-file-output='${outFile}'"
        }
        echo "Snyk SCA scan completed successfully using credential: ${snykTokenCredId}"
        echo "Report saved to: ${outFile}"
    } catch (Exception e) {
        if (e.getMessage().contains("Credentials") || e.getMessage().contains("not found")) {
            error """
Snyk token credential '${snykTokenCredId}' not found in Jenkins.
Please check the credential configuration in: Manage Jenkins > Manage Credentials
Make sure the credential ID matches exactly: '${snykTokenCredId}'
"""
        } else {
            error "Snyk SCA scan failed: ${e.getMessage()}"
        }
    }
}
