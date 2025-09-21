def call(String output = null, String dockerfile = 'Dockerfile', String tokenCredId = 'snyk') {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/snyk-image.json"
    String awkFile = '.jenkins-awk-extract-image.awk'
    
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    writeFile file: awkFile, text: libraryResource('utils/awk-extract-image.awk')
    try {
        withCredentials([string(credentialsId: tokenCredId, variable: 'SNYK_TOKEN')]) {
            sh """
                dockerImageName=\$(awk -f '${awkFile}' '${dockerfile}')
                snyk container test --severity-threshold=high --json-file-output='${outFile}' "\${dockerImageName}"
            """
        }
    } finally {
        sh "rm -f '${awkFile}'"
    }
}
