def call(Map cfg = [:]) { runWithCatch('OPA Conftest') {
  String out = cfg.output ?: 'report/opa-report.sarif'
  String policyDir = cfg.policyDir ?: 'policy'
    sh """
      mkdir -p report
      conftest test --parser dockerfile -p ${policyDir} Dockerfile --output sarif > ${out}
    """
  }
}
