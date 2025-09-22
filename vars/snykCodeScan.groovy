def call(String output = null, String snykTokenCredId = null) {
    if (!snykTokenCredId) {
        error """
snykTokenCredId parameter is required for Snyk Code scan.
Please provide the Snyk token credential ID configured in Jenkins.
Example: call(snykTokenCredId: 'snyk-token')
"""
    }
    
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/snyk-code.json"
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    try {
        withCredentials([string(credentialsId: snykTokenCredId, variable: 'SNYK_TOKEN')]) {
            sh "snyk code test --severity-threshold=high --json-file-output='${outFile}'"
        }
        echo "Snyk Code scan completed successfully using credential: ${snykTokenCredId}"
        echo "Report saved to: ${outFile}"
    } catch (Exception e) {
        if (e.getMessage().contains("Credentials") || e.getMessage().contains("not found")) {
            error """
Snyk token credential '${snykTokenCredId}' not found in Jenkins.
Please check the credential configuration in: Manage Jenkins > Manage Credentials
Make sure the credential ID matches exactly: '${snykTokenCredId}'
"""
        } else {
            error "Snyk Code scan failed: ${e.getMessage()}"
        }
    }
}
