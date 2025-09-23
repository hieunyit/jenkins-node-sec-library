def call(Object arg = null) {
    String digestFile = 'digest.txt'
    String imageName = 'docker.io/hieuny/juice-shop'
    String keyCredId = 'cosign-private-key'
    String passCredId = 'cosign-pass'
    
    if (arg instanceof CharSequence) {
        imageName = arg.toString().trim()
    } else if (arg instanceof Map) {
        digestFile = arg.digestFile ?: 'digest.txt'
        imageName = arg.imageName ?: 'docker.io/hieuny/juice-shop'
        keyCredId = arg.keyCredId ?: 'cosign-private-key'
        passCredId = arg.passCredId ?: 'cosign-pass'
    }
    
    withCredentials([
        file(credentialsId: keyCredId, variable: 'COSIGN_KEY'),
        string(credentialsId: passCredId, variable: 'COSIGN_PASSWORD')
    ]) {
        sh """
            DIGEST=\$(cat '${digestFile}')
            cosign sign -y --key \$COSIGN_KEY '${imageName}@'\$DIGEST
            cosign clean '${imageName}:'\$DIGEST.sig
        """
    }
}
