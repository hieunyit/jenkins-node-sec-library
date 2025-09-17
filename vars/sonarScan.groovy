def call(Map cfg = [:]) {
  String projectKey = cfg.projectKey ?: 'juice-shop'
  String exclusions = cfg.exclusions ?: '**/test/**'
  withSonarQubeEnv(cfg.server ?: 'SonarQube Server') {
    sh '''
      ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
      -Dsonar.projectKey=${projectKey} \
      -Dsonar.exclusions=${exclusions}
    '''
  }
}
