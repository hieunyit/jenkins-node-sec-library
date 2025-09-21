def call(String output = null, String dockerfile = 'Dockerfile', String policyDir = 'policy') {
    String outFile = output ?: "${env.REPORT_DIR ?: 'report'}/opa-report.sarif"
    
    sh """
        mkdir -p "\$(dirname '${outFile}')"
        conftest test --parser dockerfile -p '${policyDir}' '${dockerfile}' --output sarif > '${outFile}'
    """
}
