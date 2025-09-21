def call(String output = null, String tokenCredId = 'snyk') {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/snyk-code.json"
    
    sh "mkdir -p \"\$(dirname '${outFile}')\""
    
    withCredentials([string(credentialsId: tokenCredId, variable: 'SNYK_TOKEN')]) {
        sh "snyk code test --severity-threshold=high --json-file-output='${outFile}'"
    }
}
