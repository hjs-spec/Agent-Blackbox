# Contributing to Agent Blame-Finder

Thanks for your interest! We welcome all contributions.

## 📦 Development Setup

```bash
# Clone the repo
git clone https://github.com/hjs-spec/agent-blame-finder.git
cd agent-blame-finder

# Python development
pip install -e ".[dev]"

# Rust core development
cd core && cargo build
```

## 🧪 Running Tests

```bash
# Python tests
pytest tests/

# Rust tests
cd core && cargo test
```

## 📝 Pull Request Guidelines

1. **One feature per PR** — Keep changes focused
2. **Add tests** — For bug fixes or new features
3. **Update docs** — If changing user-facing behavior
4. **Sign your commits** — `git commit -s`

## 🐛 Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Python version, etc.)

## 💡 Feature Requests

Open an issue describing:
- The problem you're solving
- How it should work
- Any alternatives considered

## 📄 Code of Conduct

Be respectful. We're here to build something useful, not to argue.

---

Thanks for helping make Agent Blame-Finder better! 🚀
```
