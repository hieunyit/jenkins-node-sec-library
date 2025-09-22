def call(String imageName = null, String imageTag = null, String keyCredId = 'cosign-public-key') {
    String image = imageName ?: env.IMAGE_NAME
    String tag = imageTag ?: env.VERSION
    
    if (!image) {
        error "IMAGE_NAME must be provided or set as environment variable"
    }
    if (!tag) {
        error "VERSION must be provided or set as environment variable"
    }
    
    withCredentials([file(credentialsId: keyCredId, variable: 'COSIGN_PUBLIC_KEY')]) {
        sh """
            echo "🔍 Verifying image: ${image}:${tag}"
            
            if cosign verify --key \$COSIGN_PUBLIC_KEY '${image}:${tag}' > /dev/null; then
                echo "✅ Cosign verify OK: ${image}:${tag}"
            else
                echo "❌ Cosign verify FAILED: ${image}:${tag}"
                exit 1
            fi
        """
    }
}
