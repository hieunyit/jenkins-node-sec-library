def call(Object arg = null) {
    String keyCredId = 'cosign-public-key'
    String imageTag = '${env.VERSION}'
    
    if (arg instanceof CharSequence) {
        imageTag = arg.toString().trim()
    } else if (arg instanceof Map) {
        keyCredId = arg.keyCredId ?: 'cosign-public-key'
        imageTag = arg.imageTag ?: '${env.VERSION}'
    }
    
    withCredentials([file(credentialsId: keyCredId, variable: 'COSIGN_PUBLIC_KEY')]) {
        sh '''
            if cosign verify --key $COSIGN_PUBLIC_KEY ${IMAGE_NAME}:${imageTag} > /dev/null; then
                echo "✅ Cosign verify OK: ${IMAGE_NAME}:${imageTag}"
                exit 0
            else
                echo "❌ Cosign verify FAILED: ${IMAGE_NAME}:${imageTag}"
                exit 1
            fi
        '''
    }
}
