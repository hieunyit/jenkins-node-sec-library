# Jenkins Node Security Library

This shared library provides Jenkins pipeline steps for running a suite of security checks
against Node.js projects, including container image scanning, dependency analysis, static
analysis and policy enforcement for Dockerfiles.

## Included Jenkins Steps

| Step | Description |
| --- | --- |
| `snykImageScan` | Scan container images with Snyk Container. |
| `trivyScan` | Scan container images with Trivy. |
| `snykSca` | Run Snyk SCA against project dependencies. |
| `snykCodeScan` | Perform Snyk Code static analysis. |
| `semgrepScan` | Execute Semgrep rules. |
| `npmAudit` | Run `npm audit` with SARIF output. |
| `retireJsScan` | Run retire.js audit with SARIF output. |
| `gitleaksScan` | Detect leaked secrets with Gitleaks. |
| `conftestDockerfile` | Evaluate Dockerfiles against the bundled OPA policy. |

Each step accepts optional parameters to control report locations. Reports default to the
`report/` directory inside the workspace when an explicit path is not provided.

An end-to-end pipeline example that demonstrates how to wire these steps together is
available at `examples/Jenkinsfile`.

## Dockerfile Policy

The `conftestDockerfile` step looks for Rego policies in the `policy/` directory by default.
This repository now includes a baseline `policy/Dockerfile.rego` policy with the following
checks:

- Base images must pin to a specific tag and avoid the `latest` tag.
- Dockerfiles must declare a non-root `USER`.
- `ADD` instructions are disallowed in favour of `COPY`.
- `apk add` and `apt/apt-get install` package operations must pin explicit versions.

To test a Dockerfile locally with Conftest:

```bash
conftest test --parser dockerfile -p policy path/to/Dockerfile
```

## Example Jenkinsfile

The sample pipeline in `examples/Jenkinsfile` shows how to load this shared library and run
the scanners with custom report locations. Each step ensures the parent directory of the
`output` path exists, so you can tailor report destinations to suit your archiving strategy.
The example finishes by collecting every report under the `reports/` directory with the
`archiveArtifacts` step for downstream visibility.

## Development

1. Update or add Jenkins pipeline steps under the `vars/` directory.
2. Keep shared Groovy helpers in `src/`.
3. Place reusable resources (scripts, policies, etc.) under `resources/` or their own
   top-level folders.
4. Run the relevant scanners locally when possible to validate behaviour before pushing
   changes.
