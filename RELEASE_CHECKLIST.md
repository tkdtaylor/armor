# Release checklist

Use this as the gate before tagging any `v*.*.*` release. Most of it is automated under `make release-check`; the manual items are explicit.

## Pre-flight

- [ ] On `main`: `git checkout main && git pull --ff-only`
- [ ] Working tree is clean: `git status` shows nothing
- [ ] Version bumped in `pyproject.toml` (`[project] version = "X.Y.Z"`)
- [ ] `CHANGELOG.md` has an entry for the new version under a dated header (move items from `[Unreleased]`)

## Automated verification

```bash
make release-check
```

Stages, in order:

1. `make check` — lint + mypy + unit + eval corpus
2. `make fitness` — architecture invariants (no-network-in-daemon, no-canary-in-logs, validator soft-fail, P95 latency, cold-start)
3. `make demo` — end-to-end scenario on a real daemon (input injection block + canary exfiltration block)
4. `examples/*.py --offline-smoke` — every published example exits 0 in offline mode (catches example bit-rot)

A failing stage prints which one failed and the recipe exits non-zero. Do not proceed past a failure.

Optional: add the Docker stage by setting `DOCKER=1`. Requires `armor-dev` image to be built (`docker compose -f docker/docker-compose.yml build dev`):

```bash
DOCKER=1 make release-check
```

## Manual verification

- [ ] Eyeball the demo output for surprises (`make demo` and read the stderr blocks)
- [ ] `git log --oneline main..` against the previous tag — no commits you don't recognize
- [ ] `LICENSE` and `SECURITY.md` unchanged (or, if intentional, captured in CHANGELOG)
- [ ] No real canary values in the diff: `git diff <prev-tag>..main | grep -E 'AKIA[A-Z0-9]{16}'` returns nothing (or only `FAKE`/`EXAMPLE` matches)

## Tag and push

```bash
VERSION=vX.Y.Z  # match pyproject.toml (e.g. v0.9.0)
git tag -a "$VERSION" -m "armor $VERSION"
git push origin "$VERSION"
```

## Post-tag

- [ ] [`.github/workflows/release.yml`](.github/workflows/release.yml) ran and succeeded (check `gh run list` or the Actions tab)
- [ ] GHCR multi-arch image lands at `ghcr.io/tkdtaylor/armor:$VERSION` and `:latest`
- [ ] PyPI publish succeeded for `armor-ai==$VERSION`
- [ ] CHANGELOG entry under `[Unreleased]` is back to empty/template

## If something goes wrong

- A failing `make release-check` stage is the first signal. Read its output, fix the underlying issue (do not bypass), and re-run.
- A failing post-tag workflow can be re-run from the GitHub Actions UI without re-tagging — the workflow is idempotent.
- If the tag itself was wrong (e.g. wrong version), delete it both locally and on the remote *before* the post-tag workflows publish, then re-tag:
  ```bash
  git tag -d vX.Y.Z
  git push origin :refs/tags/vX.Y.Z
  ```
- For the worst case (history needs rewriting after a leak landed in a tagged release), keep a local `--mirror` clone of the pre-tag tree as your recovery checkpoint and consult your local incident notes.
