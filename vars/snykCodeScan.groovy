def call(String snykTokenCredId = null) {
    if (!snykTokenCredId) {
        error """
snykTokenCredId parameter is required for Snyk Code scan.
Please provide the Snyk token credential ID configured in Jenkins.
Example: snykCodeScan('snyk-token')
"""
    }

    sh "mkdir -p report"
    
    try {
        withCredentials([string(credentialsId: snykTokenCredId, variable: 'SNYK_TOKEN')]) {
            sh "snyk code test --severity-threshold=high --json-file-output=report/snyk-code.json"
        }
        echo "Snyk Code scan completed successfully using credential: ${snykTokenCredId}"
        echo "Report saved to: report/snyk-code.json"
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
