# Post-Release Checklist

This checklist is run by the release engineer **immediately after pushing a tag** (e.g., `git tag v0.9.0 && git push origin v0.9.0`). The release workflow will execute automatically; this manual checklist verifies that the published artifacts work as expected.

Complete all items before announcing the release publicly.

## Automated Workflow Verification (10–15 min)

- [ ] Watch the GitHub Actions run for the tag:
  ```bash
  gh run watch <run-id> --exit-status
  ```
  All jobs (build multi-arch image, publish to PyPI, smoke test) must pass green.

- [ ] Verify the GitHub Release was created:
  ```bash
  gh release view <tag>
  ```
  Release notes should be auto-generated from CHANGELOG.md.

- [ ] Verify PyPI release:
  ```bash
  curl -s https://pypi.org/pypi/armor-ai/json | jq '.releases | keys | .[-1]'
  ```
  Should show the new version (e.g., `0.9.0` or `0.9.0rc1`).

## Fresh Container Verification (5–10 min)

- [ ] Pull the fresh image from GHCR:
  ```bash
  docker pull ghcr.io/<owner>/armor:<version>
  ```
  Replace `<owner>` with the GitHub username and `<version>` with the tag (e.g., `0.9.0-rc1` → `0.9.0-rc1`).

- [ ] Verify the CLI entrypoint in a fresh container:
  ```bash
  docker run --rm --entrypoint armor ghcr.io/<owner>/armor:<version> --help
  ```
  Should display the help text for the `armor` CLI.

- [ ] Start the daemon image and verify health from inside the container:
  ```bash
  docker run -d --name armor-release-smoke ghcr.io/<owner>/armor:<version>
  ok=0
  for i in {1..30}; do
    if docker exec armor-release-smoke armor health; then
      ok=1
      break
    fi
    sleep 2
  done
  docker rm -f armor-release-smoke
  test "$ok" -eq 1
  ```
  The runtime image is intentionally the daemon image, not the dev/test image;
  the full `make demo` gate runs before tagging via `make release-check`.

## Fresh PyPI Install Verification (5–10 min)

In a **clean Python 3.12+ venv**:

- [ ] Install the package:
  ```bash
  python -m venv /tmp/armor-test
  source /tmp/armor-test/bin/activate
  pip install armor-ai==<version>
  ```

- [ ] Verify the version:
  ```bash
  armor --version
  ```
  Should output `armor <version>`.

- [ ] Verify the import package and CLI version:
  ```bash
  python -c "import armor; print(armor.__version__)"
  armor --version
  ```
  Both should show the published version. Daemon runtime verification is covered
  by the container smoke above because the PyPI wheel does not include model
  weights.

## Hook Installer Verification (5 min)

- [ ] Run the hook installer:
  ```bash
  armor hooks install
  ```
  Should create or update `./.claude/settings.json`.

- [ ] Inspect the generated config:
  ```bash
  cat ./.claude/settings.json | jq '.hooks' 2>/dev/null | head -20
  ```
  Should show the armor hooks for UserPromptSubmit, PreToolUse, PostToolUse, Stop.

## Documentation Check (5 min)

- [ ] Verify the README's Getting Started section is accurate:
  ```bash
  cat README.md | grep -A 10 "## Getting started"
  ```
  Both the container path (`docker run ghcr.io/...`) and PyPI path (`pip install armor-ai`) should be present.

- [ ] Verify the installed package contents and CLI entrypoint:
  ```bash
  python -c "import armor; print(armor.__version__)"
  armor --help
  ```
  The wheel ships the `armor` import package and CLI entrypoint. Repository
  examples remain source-tree examples and are smoke-tested before tagging by
  `make release-check`.

## Sign-Off

- [ ] All items above are checked and passing.
- [ ] **Release readiness:** the artifact is production-ready and meets the published specification.
- [ ] **Announcement:** post a release note to the project's preferred channel (GitHub Discussions, mailing list, etc.).

---

## Troubleshooting

### PyPI publish fails

- Check that the **trusted-publisher relationship** is configured on PyPI:
  - Go to https://pypi.org/manage/project/armor-ai/publishing/
  - Ensure GitHub org + repo + branch are registered.
- Verify that the `pypa/gh-action-pypi-publish` job has `id-token: write` permission (see `.github/workflows/release.yml`).

### GHCR push fails

- Check Docker authentication:
  ```bash
  echo $CR_PAT | docker login ghcr.io -u <github-username> --password-stdin
  ```
- Ensure the GitHub org allows public images (Settings → Packages → Public).

### Model download times out

- The Dockerfile downloads the embedding model (`all-MiniLM-L6-v2`) during build. If the Hugging Face Hub is slow, the build may time out.
- Increase the timeout in `.github/workflows/release.yml` or pre-cache the model layer.

### Smoke test in the container fails

- Check `docker logs armor-release-smoke` for daemon startup errors.
- Confirm the image contains `/models/active.gguf` and that `/var/run/armor`
  is writable by the unprivileged `armor` user.
- Re-run the `docker exec armor-release-smoke armor health` loop manually to
  separate slow startup from a hard daemon failure.
