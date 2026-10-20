# Contributing to DataTrust AI

We welcome contributions! Here is how you can help:

1. **Fork** the repository.
2. **Clone** your fork: `git clone https://github.com/your-username/datatrust-ai.git`
3. **Install** dependencies: `pip install -e .`
4. **Create a branch**: `git checkout -b feature/your-feature-name`
5. **Make your changes** and run tests: `python -m unittest discover tests`
6. **Push** and open a **Pull Request**.

## Adding New Patterns
To add new PII or Secret patterns, edit `datatrust_ai/patterns/` and add corresponding tests in `tests/`.
