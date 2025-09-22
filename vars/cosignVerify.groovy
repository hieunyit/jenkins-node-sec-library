def call(String imageName = null, String imageTag = null, String cosignPubKeyCredId = null) {
    // Validate required parameters
    if (!cosignPubKeyCredId) {
        error """
cosignPubKeyCredId parameter is required for Cosign Verify Image.
Please provide the Cosign Public Key credential ID.
Example: call(imageName: 'my-app', imageTag: 'v1.0.0', cosignPubKeyCredId: 'cosign-public-key')
"""
    }
    
    if (!imageName) {
        error """
imageName parameter is required for Cosign Verify Image.
Please provide the Docker image name.
Example: call(imageName: 'my-app', imageTag: 'v1.0.0', cosignPubKeyCredId: 'cosign-public-key')
"""
    }
    
    if (!imageTag) {
        error """
imageTag parameter is required for Cosign Verify Image.
Please provide the image tag.
Example: call(imageName: 'my-app', imageTag: 'v1.0.0', cosignPubKeyCredId: 'cosign-public-key')
"""
    }
    
    String fullImageName = "${imageName}:${imageTag}"
    
    try {
        withCredentials([file(credentialsId: cosignPubKeyCredId, variable: 'COSIGN_PUBLIC_KEY')]) {
            sh """
                echo "🔍 Verifying image signature: ${fullImageName}"
                
                if cosign verify --key \$COSIGN_PUBLIC_KEY '${fullImageName}' > /dev/null 2>&1; then
                    echo "✅ Cosign signature verification SUCCESS: ${fullImageName}"
                else
                    echo "❌ Cosign signature verification FAILED: ${fullImageName}"
                    exit 1
                fi
            """
        }
        echo "Cosign verification completed successfully"
        echo "Image: ${fullImageName}"
        echo "Public Key Credential: ${cosignPubKeyCredId}"
    } catch (Exception e) {
        if (e.getMessage().contains("Credentials") || e.getMessage().contains("not found")) {
            error """
Cosign public key credential '${cosignPubKeyCredId}' not found in Jenkins.
Please check the credential configuration in: Manage Jenkins > Manage Credentials
Make sure the credential ID matches exactly: '${cosignPubKeyCredId}'
"""
        } else if (e.getMessage().contains("cosign: command not found")) {
            error """
Cosign tool not found. Please install Cosign or ensure it's available in PATH.
Check Cosign installation: https://docs.sigstore.dev/cosign/installation
"""
        } else {
            error "Cosign verification failed: ${e.getMessage()}"
        }
    }
}
