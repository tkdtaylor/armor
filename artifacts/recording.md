# Demo recording — `artifacts/demo.svg`

## What this is

`artifacts/demo.svg` is the visual that the project README embeds at the top so a visitor can see armor working in 30 seconds without leaving the page. The current file is a **hand-crafted SVG approximation** of the `make demo` flow (input injection block + canary exfiltration block + cleanup), authored alongside task 059. It renders inline in GitHub markdown, no external dependency.

## Replacing it with a real asciicast

Replace the static SVG with a real terminal recording when convenient — the static version is a placeholder that prevents the README from looking empty until the recording lands.

### Tools

- [`asciinema`](https://asciinema.org/) — terminal recorder. `cargo install asciinema` or your package manager.
- [`agg`](https://github.com/asciinema/agg) — official asciinema → animated SVG converter. `cargo install --git https://github.com/asciinema/agg`.

### Recording

```bash
# 1. Set a fixed terminal size for reproducibility (80x24 keeps the SVG small).
resize -s 24 80   # xterm; on tmux: `tmux resize-window -x 80 -y 24`

# 2. Record the demo. Re-record cleanly if you hit a typo or pause.
asciinema rec artifacts/demo-recording.cast \
    --command "make demo" \
    --idle-time-limit 1.0 \
    --title "armor end-to-end demo"

# 3. Convert to animated SVG. Tweak --speed and --font-size to taste.
agg artifacts/demo-recording.cast artifacts/demo.svg \
    --theme github-dark \
    --speed 1.5 \
    --font-size 14
```

### Sanity checks before committing

```bash
# Size — keep under 1 MB so GitHub renders it without complaint.
ls -lh artifacts/demo.svg

# No real canary values leaked into the recording. `make demo` substitutes
# canary_id for value, so this should naturally return nothing.
grep -E 'AKIA[A-Z0-9]{16}' artifacts/demo.svg && echo "FAIL: leaked canary" || echo "OK: no canary"

# Render check — open the SVG in a browser to confirm it actually plays.
xdg-open artifacts/demo.svg
```

If `make demo` output drifts (new attack categories, different exit codes, etc.), re-record. The fitness check (`tests/fitness/test_demo_recording.py`) only asserts the artifact exists and is sized reasonably; content drift is for the operator to catch on visual inspection.

## Wall-clock target

20–120 seconds. Short enough to actually watch; long enough to be informative. If a real `make demo` run exceeds 120 s (e.g. cold model load), use `agg --speed 2.0` or trim the cast file with `asciinema cat` + manual edit.
