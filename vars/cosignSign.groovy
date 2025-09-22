def call(String digestFile = 'digest.txt', String imageName = 'docker.io/hieuny/juice-shop', String keyCredId = 'cosign-private-key', String passCredId = 'cosign-pass') {
    withCredentials([
        file(credentialsId: keyCredId, variable: 'COSIGN_KEY'),
        string(credentialsId: passCredId, variable: 'COSIGN_PASSWORD')
    ]) {
        sh """
            DIGEST=\$(cat '${digestFile}')
            cosign sign -y --key \$COSIGN_KEY '${imageName}@'\$DIGEST
        """
    }
}
