# spdx-identity

Stable identity resolution for SPDX 3.0.1 elements. Computes deterministic natural keys from nondeterministic `spdxId` values using a three-tier identity strategy, enabling reliable element matching across independently generated SBOMs.

## Why This Exists

SPDX 3.0.1 SBOM generators produce different `spdxId` values for the same logical element on every run. This makes it impossible to compare, correlate, or track elements across SBOM versions using `spdxId` alone. `spdx-identity` solves this by resolving each element to a stable identity key based on **what it represents** rather than its arbitrary identifier.

**Use cases:**
- **SBOM diffing** -- Match elements across baseline and target SBOMs to detect real changes
- **Impact analysis** -- Correlate a single SBOM's elements with known vulnerability databases using stable keys
- **Deduplication** -- Identify duplicate elements within or across SBOMs
- **Provenance tracking** -- Trace elements across the software supply chain

## Installation

```bash
# Using UV (recommended)
uv add spdx-identity

# Using pip
pip install spdx-identity
```

**Requirements:** Python 3.12+ | Zero external dependencies (stdlib only)

## Quick Start

### Single-Element Resolution

```python
from spdx_identity import IdentityResolver

resolver = IdentityResolver()

# Tier 1: Permanent identifier (PURL)
element = {
    "spdxId": "ABC/SPDXRef-gnrtd5",
    "type": "software_Package",
    "name": "pyyaml",
    "packageVersion": "6.0.1",
    "packageUrl": "pkg:pypi/pyyaml@6.0.1?tag_id=uuid-123",
}
key, tier = resolver.compute_identity_key(element)
# key = "perm::pkg:pypi/pyyaml", tier = 1

# Tier 2: Composite key (type + name)
agent = {
    "spdxId": "XYZ/SPDXRef-gnrtd1",
    "type": "Agent",
    "name": "syft",
}
key, tier = resolver.compute_identity_key(agent)
# key = "Agent::syft", tier = 2

# Tier 3: Content hash (fallback)
license_text = {
    "spdxId": "XYZ/SPDXRef-lic1",
    "type": "simplelicensing_SimpleLicensingText",
    "licenseText": "Permission is hereby granted...",
}
key, tier = resolver.compute_identity_key(license_text)
# key = "hash::simplelicensing_SimpleLicensingText::a1b2c3d4...", tier = 3
```

### Bulk SBOM Resolution

```python
from spdx_identity import resolve_sbom

elements = [
    {"spdxId": "id-1", "type": "software_Package", "name": "flask",
     "packageUrl": "pkg:pypi/flask@2.0"},
    {"spdxId": "id-2", "type": "Agent", "name": "syft"},
    {"spdxId": "id-3", "type": "software_File", "name": "app.py"},
]

result = resolve_sbom(elements)
# {
#     "id-1": ("perm::pkg:pypi/flask", 1),
#     "id-2": ("Agent::syft", 2),
#     "id-3": ("software_File::app.py", 2),
# }
```

### PURL Normalization

```python
from spdx_identity import PURLNormalizer

normalizer = PURLNormalizer()

# Normalize a PURL (lowercases type/namespace/name, sorts qualifiers)
normalized = normalizer.normalize_purl("pkg:PyPI/PyYAML@6.0.1?tag_id=abc")
# "pkg:pypi/pyyaml@6.0.1?tag_id=abc"

# Check PURL equivalence
normalizer.are_purls_equivalent(
    "pkg:PyPI/PyYAML@6.0.1",
    "pkg:pypi/pyyaml@6.0.1",
)
# True

# Extract PURL components
components = normalizer.extract_purl_components("pkg:npm/@scope/name@1.0.0")
# {"scheme": "pkg", "type": "npm", "namespace": "@scope",
#  "name": "name", "version": "1.0.0", "qualifiers": {}, "subpath": ""}
```

### Post-Match Validation

```python
from spdx_identity import IdentityResolver

resolver = IdentityResolver()

old = {"type": "software_Package", "name": "foo", "packageVersion": "1.0"}
new = {"type": "software_Package", "name": "foo", "packageVersion": "1.1"}

# Returns True -- only version differs (well under 70% threshold)
resolver.validate_match(old, new)

# Returns False -- >70% of comparable properties differ (8 of 10 props = 80%)
unrelated = {
    "type": "software_Package", "name": "foo",
    "supplier": "X", "description": "A", "downloadLocation": "http://a.com",
    "homepage": "http://b.com", "summary": "x", "sourceInfo": "y", "comment": "z",
}
resolver.validate_match(old, unrelated)
```

### Relationship Identity Keys

```python
from spdx_identity import IdentityResolver

resolver = IdentityResolver()

rel = {
    "type": "Relationship",
    "from": "pkg:pypi/flask",
    "relationshipType": "DEPENDS_ON",
    "to": ["pkg:pypi/werkzeug", "pkg:pypi/jinja2"],
}

key = resolver.compute_relationship_identity_key(rel)
# "rel::Relationship::pkg:pypi/flask::DEPENDS_ON::pkg:pypi/jinja2|pkg:pypi/werkzeug::"
```

## API Reference

### `IdentityResolver`

| Constructor / Method | Description |
|----------------------|-------------|
| `IdentityResolver(purl_normalizer=None)` | Optional `PURLNormalizer` for dependency injection (default: creates one internally) |
| `compute_identity_key(element)` | Returns `(identity_key, tier)` for an SPDX element dict |
| `validate_match(old_element, new_element)` | Returns `False` if >70% of non-reference properties differ |
| `compute_relationship_identity_key(relationship)` | Returns a deterministic identity key for a relationship dict |

### `PURLNormalizer`

| Method | Description |
|--------|-------------|
| `normalize_purl(purl)` | Normalizes a PURL string (lowercase, sorted qualifiers) |
| `are_purls_equivalent(purl1, purl2)` | Checks equivalence after normalization |
| `extract_purl_components(purl)` | Parses a PURL into component parts |

### `resolve_sbom(elements)`

Convenience function that creates an `IdentityResolver` and resolves all elements in a list. Returns `{spdx_id: (identity_key, tier)}`.

### `REFERENCE_FIELDS`

A `frozenset[str]` of property names containing spdxId references. These are excluded from content hashing and structural comparison. Includes: `spdxId`, `@id`, `creationInfo`, `suppliedBy`, `originatedBy`, `from`, `to`, `element`, `rootElement`, `subject`, `snippetFromFile`, `assessedElement`, `member`, `subjectLicense`, `subjectExtendableLicense`, `subjectAddition`, `createdBy`, `createdUsing`.

## Algorithm Details

For the full algorithm specification -- including tier details, PURL/CPE normalization rules, composite key tables by SPDX profile, and worked examples -- see [docs/IDENTITY_RESOLUTION.md](docs/IDENTITY_RESOLUTION.md).

## Development

```bash
# Clone and install
git clone <repository-url>
cd spdx_identity
uv sync

# Run tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=spdx_identity --cov-report=term-missing
```

## License

MIT
