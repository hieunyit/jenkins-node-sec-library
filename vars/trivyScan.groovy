def call(String output = null, String dockerfile = null) {
    // Validate required parameter
    if (!dockerfile) {
        error """
dockerfile parameter is required for Trivy scan.
Please provide the path to Dockerfile.
Example: call(dockerfile: 'Dockerfile')
"""
    }
    
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/trivy-report.json"
    String awkFile = '.awk-extract-image.awk'

    sh "mkdir -p \"\$(dirname '${outFile}')\""

    sh "test -f '${dockerfile}' || (echo 'Dockerfile not found: ${dockerfile}' && exit 1)"
    
    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
    
    try {
        sh """
            dockerImageName=\$(awk -f '${awkFile}' '${dockerfile}')
            if [ -z "\${dockerImageName}" ]; then
                echo "Could not extract Docker image name from ${dockerfile}"
                exit 1
            fi
            echo "Scanning Docker image with Trivy: \${dockerImageName}"
            trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress --quiet -f json -o '${outFile}' "\${dockerImageName}"
        """
        echo "Trivy scan completed successfully"
        echo "Dockerfile: ${dockerfile}"
        echo "Report saved to: ${outFile}"
    } catch (Exception e) {
        if (e.getMessage().contains("trivy: command not found") || e.getMessage().contains("trivy: not found")) {
            error """
Trivy tool not found. Please install Trivy or ensure it's available in PATH.
Check Trivy installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
"""
        } else {
            error "Trivy scan failed: ${e.getMessage()}"
        }
    } finally {
        sh "rm -f '${awkFile}'"
    }
}
