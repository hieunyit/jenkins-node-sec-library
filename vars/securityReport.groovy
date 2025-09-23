def call(Map params = [:]) {
    // Extract parameters from map
    String reportDir = params.reportDir ?: "${env.REPORT_DIR ?: 'report'}"
    String pythonExecutable = params.pythonExecutable ?: 'python3'
    
    // Check if report directory exists
    sh "test -d '${reportDir}' || (echo 'Report directory not found: ${reportDir}' && exit 1)"
    
    String scriptFile = '.vuln_report.py'
    
    try {
        // Load Python script from library resources
        writeFile file: scriptFile, text: libraryResource('scripts/vuln_report.py')
        
        sh """
            echo "📊 Running security report aggregator"
            echo "📁 Report Directory: ${reportDir}"
            echo "----------------------------------------"
            
            ${pythonExecutable} '${scriptFile}' '${reportDir}'/*.sarif '${reportDir}'/*.json --output-html=report/repor-security.html  --output-json=report/repor-security.json
        """
        
        echo "✅ Security report aggregation completed"
        
    } catch (Exception e) {
        if (e.getMessage().contains("python") && e.getMessage().contains("not found")) {
            error """
Python executable '${pythonExecutable}' not found.
Please install Python or specify correct Python executable.
"""
        } else if (e.getMessage().contains("libraryResource")) {
            error """
Security report aggregator script not found in library resources.
Please ensure 'scripts/vuln_report.py' exists in library resources.
"""
        } else {
            error "Security report aggregation failed: ${e.getMessage()}"
        }
    } finally {
        // Clean up temporary script file
        sh "rm -f '${scriptFile}'"
    }
}
