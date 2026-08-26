# Contributing to Raucle

Thank you for your interest in contributing to Raucle. This library is the open-source core of the [Raucle](https://raucle.com) AI security platform.

## Developer Certificate of Origin (DCO)

All contributions must be signed off in accordance with the
[Developer Certificate of Origin (DCO)](./DCO). This certifies that you wrote
or have the right to submit the code you are contributing.

Every commit in your pull request **must** include a `Signed-off-by` line:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add this automatically by committing with the `-s` flag:

```bash
git commit -s -m "Add new detection rule for encoding bypass"
```

The DCO check runs automatically on all pull requests and must pass before merging.

## Getting Started

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/raucle.git
cd raucle

# Install in development mode
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run a quick scan
raucle scan "test prompt"
```

## What We Welcome

### Detection Rules (most impactful)

New YAML detection rules are the easiest and most impactful contribution. Add rules to `rules/` following this format:

```yaml
- id: COMMUNITY-001
  name: my_detection_rule
  category: direct_injection  # or: jailbreak, data_loss, tool_poisoning, evasion
  technique: technique_name
  severity: HIGH              # LOW | MEDIUM | HIGH | CRITICAL
  patterns:
    - '(?i)your regex here'
  score: 0.80                 # 0.0 to 1.0
```

Include test cases showing what should and should not match.

### Bug Fixes

- Clear description of the bug and how to reproduce it
- Tests that demonstrate the fix

### New Features

- Open an issue first to discuss the approach
- Keep changes focused and minimal
- Include tests

### Documentation

- Improvements to README, docstrings, or examples

## What We Don't Accept

- Changes that add heavy dependencies to the core library (keep it lightweight)
- ML model weights in the repository (use optional downloads)
- Changes to the license

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make changes with signed-off commits (`git commit -s`)
4. Write or update tests
5. Ensure `python -m pytest tests/ -v` passes
6. Submit a pull request against `main`
7. Wait for review from @craigamcw

All PRs require approval from a maintainer before merging.

## Code Style

- Follow PEP 8
- Use type hints
- Run `ruff check` and `ruff format` before submitting
- Keep functions focused and well-named

## License

By contributing to Raucle, you agree that your contributions will be
licensed under the **Apache License, Version 2.0** under which the project is
released (see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md)). This follows
the standard "inbound = outbound" model: what you contribute is licensed under
the same terms as the project.

Every contribution requires a [DCO](DCO) sign-off (`git commit -s`), which
certifies you have the right to submit it. No separate copyright-assignment CLA
is required.
# CI retrigger
