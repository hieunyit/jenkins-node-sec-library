def call(String output = null, String dockerfile = 'Dockerfile') {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/trivy-report.json"
    String awkFile = '.awk-extract-image.awk'
    
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
    try {
        sh """
            dockerImageName=\$(awk -f '${awkFile}' '${dockerfile}')
            trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress --quiet -f json -o '${outFile}' "\${dockerImageName}"
        """
    } finally {
        sh "rm -f '${awkFile}'"
    }
}
