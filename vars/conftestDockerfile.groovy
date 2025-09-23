def call(String dockerfile = 'Dockerfile', String policyDir = 'policy') {
    
    sh """
        mkdir -p report
        conftest test --parser dockerfile -p '${policyDir}' '${dockerfile}' --output sarif > report/opa-report.sarif
    """
}
