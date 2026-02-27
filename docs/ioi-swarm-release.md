# ioi-swarm Release Workflow

This document defines the release workflow for the Python SDK at
`ioi-swarm/python`.

## Source Of Truth

- SDK metadata: `ioi-swarm/python/pyproject.toml`
- CI/CD workflow: `.github/workflows/workflow.yml`

## Standard Release Procedure

1. Update the version in `ioi-swarm/python/pyproject.toml`.
2. Verify locally:

```bash
cd ioi-swarm/python
hatch build
ls dist/
```

3. Commit and push the version bump before tagging:

```bash
git add ioi-swarm/python/pyproject.toml
git commit -m "release: version 0.1.x"
git push origin master
```

4. Tag that exact commit and push the tag:

```bash
git tag v0.1.x
git push origin v0.1.x
```

## Recovering From A Bad Tag

If a release tag points to an older commit/version:

1. Ensure the correct version is committed and pushed to `master`.
2. Delete and recreate the tag:

```bash
git tag -d v0.1.x
git push origin :refs/tags/v0.1.x
git tag v0.1.x
git push origin v0.1.x
```

## Security Note

Releases use Trusted Publishing (OIDC) via GitHub Actions. Do not use API
tokens or username/password release credentials.

## Local Debugging Flags

- `IOI_LOG_RAW_PROMPTS=1` to include raw query/prompt/payload logs.
- `IOI_LOG_RAW_KERNEL_EVENTS=1` to include raw `KernelEvent` dumps.
