def call(String snykTokenCredId = null) {
    if (!snykTokenCredId) {
        error """
snykTokenCredId parameter is required for Snyk Container scan.
Please provide the Snyk token credential ID configured in Jenkins.
Example: snykImageScan('snyk-token')
"""
    }
    
    if (!dockerfile) {
        error """
dockerfile parameter is required for Snyk Container scan.
Please provide the path to Dockerfile.
Example: call(dockerfile: 'Dockerfile', snykTokenCredId: 'snyk-token')
"""
    }
    
    String awkFile = '.jenkins-awk-extract-image.awk'
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    sh "test -f '${dockerfile}' || (echo 'Dockerfile not found: ${dockerfile}' && exit 1)"
    
    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
    
    try {
        withCredentials([string(credentialsId: snykTokenCredId, variable: 'SNYK_TOKEN')]) {
            sh """
                dockerImageName=\$(awk -f '${awkFile}' '${dockerfile}')
                if [ -z "\${dockerImageName}" ]; then
                    echo "Could not extract Docker image name from ${dockerfile}"
                    exit 1
                fi
                echo "Scanning Docker image: \${dockerImageName}"
                snyk container test --severity-threshold=high --json-file-output=report/snyk-container.json "\${dockerImageName}"
            """
        }
        echo "Snyk Container scan completed successfully using credential: ${snykTokenCredId}"
        echo "Dockerfile: ${dockerfile}"
        echo "Report saved to: report/snyk-container.json}"
    } catch (Exception e) {
        if (e.getMessage().contains("Credentials") || e.getMessage().contains("not found")) {
            error """
Snyk token credential '${snykTokenCredId}' not found in Jenkins.
Please check the credential configuration in: Manage Jenkins > Manage Credentials
Make sure the credential ID matches exactly: '${snykTokenCredId}'
"""
        } else {
            error "Snyk Container scan failed: ${e.getMessage()}"
        }
    } finally {
        sh "rm -f '${awkFile}'"
    }
}
