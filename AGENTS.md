# Agent Instructions (CODEX)

## Project Overview

`spdx_identity` is a standalone Python package for SPDX element identity resolution. It computes stable natural keys from nondeterministic spdxIds using a three-tier identity strategy:

- **Tier 1**: Permanent identifiers (PURL, CPE, CVE, SWHID, gitoid)
- **Tier 2**: Composite keys (type + type-specific identifying properties)
- **Tier 3**: Content hash (SHA-256 of non-reference properties)

## Package and Dependency Management

**CRITICAL: Always use UV for all package and dependency management operations.**

UV is the required package manager for this repository. Never use pip, conda, poetry, or any other package manager.

### Common UV Commands

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest -v

# Run specific test
uv run pytest tests/test_resolver.py -v

# Run with coverage
uv run pytest --cov=spdx_identity --cov-report=term-missing
```

### Prohibited Commands

**NEVER use:**
- `pip install ...` — Use `uv add` instead
- Bare `python script.py` — Use `uv run python script.py` instead
- Bare `pytest` — Use `uv run pytest` instead

## Design Principles

1. **Zero external dependencies** — only Python stdlib
2. **Logging** — use `logging.getLogger(__name__)` directly (stdlib), no custom wrappers
3. **Public API** — exported from `spdx_identity/__init__.py`: `IdentityResolver`, `PURLNormalizer`, `REFERENCE_FIELDS`, `resolve_sbom()`
4. **Constants** — defined in `spdx_identity/constants.py` without underscore prefixes (public API)

## Testing

- Tests live in `tests/`
- Use `uv run pytest -v` to run all tests
- Cover Tier 1, 2, 3 identity resolution, validate_match, relationship keys, and PURL normalization
