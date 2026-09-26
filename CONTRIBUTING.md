# Contributing to Agent Blackbox

## Develop

```sh
git clone https://github.com/hjs-spec/Agent-Blackbox.git
cd Agent-Blackbox
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest tests -q
```

This repository contains the Python `agent_blackbox` package; no Rust build is required. Distribution name: `agent-blackbox-jep`. Commands: `agent-blackbox` and the compatibility alias `blame-finder`.

## Pull requests

Keep one focused change per PR, add regression coverage for changed behavior, update affected documentation, and sign off commits with `git commit -s`. Preserve existing signed archives and explicit historical readers.

Report bugs with reproduction steps, expected/actual behavior and Python version. Be respectful when reviewing contributions.
