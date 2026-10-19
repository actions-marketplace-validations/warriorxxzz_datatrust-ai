# Contributing to DataTrust AI

First off, thank you for considering contributing to DataTrust AI! It's people like you that make open-source tools better for everyone.

## How Can I Contribute?

### 1. Adding New Country Patterns
If you want to add PII patterns for your country (e.g., US SSN, UK NINO, etc.):
1. Create a new file in `guard/patterns/` (e.g., `usa.py`).
2. Add your regex patterns.
3. Update `guard/detector.py` to include your new patterns and their severity levels.
4. Update `guard/cli.py` to add friendly names for the new IDs.

### 2. Reporting Bugs
If you find a bug, please open an issue using the "Bug Report" template. Include the text you typed and what you expected to happen.

### 3. Suggesting Enhancements
Open an issue using the "Feature Request" template and describe your idea.

## Pull Request Process
1. Fork the repo and create your branch from `main`.
2. Test your changes locally.
3. Update the README.md with details of changes, if applicable.
4. Submit the pull request!
