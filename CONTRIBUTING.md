# Contributing Guidelines

We welcome contributions to **Security Log Analyzer**!

## Code Quality Standards
- Strict type hinting checked by `mypy` with zero warnings.
- Code style conforming to PEP 8 enforced by `ruff format` and `ruff check`.
- Security scanning passing with `bandit` (0 issues).
- Test coverage must maintain or exceed 90% (`pytest --cov=src/loganalyzer --cov-fail-under=90`).

## Development Workflow
1. Fork and create feature branch.
2. Run test and lint checks locally:
   ```bash
   pytest tests/ --cov=src/loganalyzer --cov-fail-under=90
   ruff check .
   ruff format --check .
   mypy src tests
   bandit -r src/ -c pyproject.toml
   ```
3. Submit Pull Request with descriptive title and commit messages.
