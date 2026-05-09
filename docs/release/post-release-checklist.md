# Post-Release Checklist

This checklist is run by the release engineer **immediately after pushing a tag** (e.g., `git tag v0.5.0 && git push origin v0.5.0`). The release workflow will execute automatically; this manual checklist verifies that the published artifacts work as expected.

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
  curl -s https://pypi.org/pypi/armor/json | jq '.releases | keys | .[-1]'
  ```
  Should show the new version (e.g., `0.5.0` or `0.5.0rc1`).

## Fresh Container Verification (5–10 min)

- [ ] Pull the fresh image from GHCR:
  ```bash
  docker pull ghcr.io/<owner>/armor:<version>
  ```
  Replace `<owner>` with the GitHub username and `<version>` with the tag (e.g., `0.5.0-rc1` → `0.5.0-rc1`).

- [ ] Start the daemon in a fresh container:
  ```bash
  docker run --rm -it ghcr.io/<owner>/armor:<version> --help
  ```
  Should display the help text for the `armor` CLI.

- [ ] Run the e2e demo inside the container:
  ```bash
  docker run --rm -it ghcr.io/<owner>/armor:<version> make demo
  ```
  Should execute both demo scenarios (direct injection block, canary exfiltration block) and report success.

  *Note:* The image must have the Makefile available. If it doesn't, run the equivalent Python commands:
  ```bash
  docker run --rm -it ghcr.io/<owner>/armor:<version> python -m tests.integration.demo
  ```

## Fresh PyPI Install Verification (5–10 min)

In a **clean Python 3.12+ venv**:

- [ ] Install the package:
  ```bash
  python -m venv /tmp/armor-test
  source /tmp/armor-test/bin/activate
  pip install ai-armor==<version>
  ```

- [ ] Verify the version:
  ```bash
  armor --version
  ```
  Should output `armor <version>`.

- [ ] Start the daemon (it should find the baked model or download it):
  ```bash
  armor daemon --socket /tmp/armor.sock --db /tmp/armor-test.db &
  sleep 2
  ```

- [ ] Run a simple smoke test:
  ```bash
  echo "ignore previous instructions" | armor check input --socket /tmp/armor.sock --session-id test-1
  ```
  Should return a block verdict (exit code 1) with details.

- [ ] Stop the daemon:
  ```bash
  kill %1 2>/dev/null || pkill -f "armor daemon"
  ```

## Hook Installer Verification (5 min)

- [ ] Run the hook installer:
  ```bash
  armor hook install
  ```
  Should output a message like:
  ```
  Hook installer would install to ~/.claude/settings.json
  ```

- [ ] Inspect the generated config:
  ```bash
  cat ~/.claude/settings.json | jq '.hooks' 2>/dev/null | head -20
  ```
  Should show the armor hooks for UserPromptSubmit, PreToolUse, PostToolUse, Stop.

  *Note:* The first time, this is a dry-run. A real `armor hook install --apply` or `armor hook apply` would commit the change to `~/.claude/settings.json` (not implemented yet in v0.4; skip if not present).

## Documentation Check (5 min)

- [ ] Verify the README's Getting Started section is accurate:
  ```bash
  cat README.md | grep -A 10 "## Getting started"
  ```
  Both the container path (`docker run ghcr.io/...`) and PyPI path (`pip install ai-armor`) should be present.

- [ ] Verify examples are available in the wheel:
  ```bash
  python -c "import importlib.resources; print(list(importlib.resources.files('armor').iterdir()))"
  ```
  Or, after install, check the site-packages:
  ```bash
  ls -la $(python -c "import armor; print(armor.__file__)" | xargs dirname)/../
  ```
  The `examples/` directory should be shipped with the wheel.

## Sign-Off

- [ ] All items above are checked and passing.
- [ ] **Release readiness:** the artifact is production-ready and meets the published specification.
- [ ] **Announcement:** post a release note to the project's preferred channel (GitHub Discussions, mailing list, etc.).

---

## Troubleshooting

### PyPI publish fails

- Check that the **trusted-publisher relationship** is configured on PyPI:
  - Go to https://pypi.org/manage/project/armor/publishing/
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

- Check that the image includes the `Makefile` and `tests/` directory (they should be in the Docker build context).
- If not, the Dockerfile's `COPY . .` may be filtering them out (check `.dockerignore`).
- Alternatively, run the smoke commands manually inside a `docker run` shell.
