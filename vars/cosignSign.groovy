def call(String imageName = null, String cosignKeyCredId = null, String cosignPassCredId = null) {
    
    if (!imageName) {
        error """
imageName parameter is required for Cosign Sign.
Please provide the Docker image name.
Example: cosignSign('digest.txt', 'docker.io/user/app', 'cosign-private-key', 'cosign-password')
"""
    }
    
    if (!cosignKeyCredId) {
        error """
cosignKeyCredId parameter is required for Cosign Sign.
Please provide the Cosign private key credential ID.
Example: cosignSign('digest.txt', 'docker.io/user/app', 'cosign-private-key', 'cosign-password')
"""
    }
    if (!cosignPassCredId) {
        error """
cosignPassCredId parameter is required for Cosign Sign.
Please provide the Cosign password credential ID.
Example: cosignSign('digest.txt', 'docker.io/user/app', 'cosign-private-key', 'cosign-password')
"""
    }
    sh "test -f '${digestFile}' || (echo 'Digest file not found: ${digestFile}' && exit 1)"
    
    try {
        withCredentials([
            file(credentialsId: cosignKeyCredId, variable: 'COSIGN_KEY'),
            string(credentialsId: cosignPassCredId, variable: 'COSIGN_PASSWORD')
        ]) {
            sh '''
                DIGEST=$(cat digest.txt)
                if [ -z "$DIGEST" ]; then
                    echo "❌ Digest file is empty: digest.txt"
                    exit 1
                fi
                
                echo "🔐 Signing image: ''' + imageName + '''@$DIGEST"
                cosign sign -y --key $COSIGN_KEY "''' + imageName + '''@$DIGEST"
                
                echo "🧹 Cleaning up signature file"
                cosign clean "''' + imageName + ''':$DIGEST.sig"
            '''
        }
        
        echo "Cosign signing completed successfully"
        echo "Digest File: digest.txt"
        echo "Image Name: ${imageName}"
        echo "Key Credential: ${cosignKeyCredId}"
        echo "Password Credential: ${cosignPassCredId}"
        
    } catch (Exception e) {
        if (e.getMessage().contains("Credentials") || e.getMessage().contains("not found")) {
            error """
Cosign credentials not found in Jenkins. Please check:
- Key credential '${cosignKeyCredId}' exists in Jenkins credentials
- Password credential '${cosignPassCredId}' exists in Jenkins credentials
Configuration: Manage Jenkins > Manage Credentials
"""
        } else if (e.getMessage().contains("cosign: command not found")) {
            error """
Cosign tool not found. Please install Cosign or ensure it's available in PATH.
Check Cosign installation: https://docs.sigstore.dev/cosign/installation
"""
        } else {
            error "Cosign signing failed: ${e.getMessage()}"
        }
    }
}
