def call(Map cfg = [:]) { runWithCatch('OWASP Dependency Check') {
  String reportDir = cfg.reportDir ?: 'report'
  String odcInst = cfg.odcInstallation ?: 'OWASP-DepCheck-12'
  dependencyCheck additionalArguments: '''
    --scan './'
    --out './${reportDir}'
    --format 'ALL'
    --exclude '**/test/files/**'
    --disableArchive
    --prettyPrint
  '''.stripIndent(), odcInstallation: odcInst
  }
}
