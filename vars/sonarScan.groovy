def call(String projectKey = null, String sonarServer = null) {
    if (!projectKey) {
        error """
projectKey parameter is required for SonarQube scan.
Please provide the SonarQube project key.
Example: call(projectKey: 'my-project', sonarServer: 'SonarQube-Server')
"""
    }
    
    if (!sonarServer) {
        error """
sonarServer parameter is required for SonarQube scan.
Please provide the SonarQube server configuration name from Jenkins.
Example: call(projectKey: 'my-project', sonarServer: 'SonarQube-Server')
"""
    }
    
    String exclusions = '**/test/**'
    
    try {
        withSonarQubeEnv(sonarServer) {
            sh """
                \${SONAR_SCANNER_HOME}/bin/sonar-scanner \\
                  -Dsonar.projectKey=${projectKey} \\
                  -Dsonar.exclusions=${exclusions}
            """
        }
        echo "SonarQube scan completed successfully"
        echo "Project Key: ${projectKey}"
        echo "Server: ${sonarServer}"
    } catch (Exception e) {
        if (e.getMessage().contains("No SonarQube server") || e.getMessage().contains("not found")) {
            error """
SonarQube server '${sonarServer}' not found in Jenkins.
Please check the SonarQube server configuration in: 
Manage Jenkins > Configure System > SonarQube servers
Make sure the server name matches exactly: '${sonarServer}'
"""
        } else if (e.getMessage().contains("SONAR_SCANNER_HOME")) {
            error """
SonarQube Scanner not found. SONAR_SCANNER_HOME is not set.
Please configure SonarQube Scanner in: 
Manage Jenkins > Global Tool Configuration > SonarQube Scanner
"""
        } else {
            error "SonarQube scan failed: ${e.getMessage()}"
        }
    }
}
