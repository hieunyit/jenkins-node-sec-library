def call(String output = null, String tokenCredId = 'snyk') {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/snyk-sca.json"
    
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    withCredentials([string(credentialsId: tokenCredId, variable: 'SNYK_TOKEN')]) {
        sh "snyk test --severity-threshold=high --json-file-output='${outFile}'"
    }
}
