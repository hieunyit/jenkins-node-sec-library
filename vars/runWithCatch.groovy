def call(String stageName, Closure body) {
  if (!stageName?.trim()) {
    error 'Stage name is required for runWithCatch.'
  }
  if (body == null) {
    error 'A body closure is required for runWithCatch.'
  }

  stage(stageName) {
    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
      body()
    }
  }
}
