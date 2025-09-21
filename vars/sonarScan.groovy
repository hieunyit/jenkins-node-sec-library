def call(String projectKey = null, String server = 'SonarQube Server') {
    String project = projectKey ?: 'juice-shop'
    String exclusions = '**/test/**'
    
    withSonarQubeEnv(server) {
        sh """
            \${SONAR_SCANNER_HOME}/bin/sonar-scanner \\
              -Dsonar.projectKey=${project} \\
              -Dsonar.exclusions=${exclusions}
        """
    }
}
