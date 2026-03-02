# Tiered Identity Resolution for SPDX 3.0.1 Elements

## Problem Statement

SPDX 3.0.1 elements carry a `spdxId` field that uniquely identifies them within a single SBOM document. However, `spdxId` is **not stable across runs**. Real-world SBOM generators produce different spdxIds for the same logical element each time they execute:

```
Run 1: AwnkYDOa50CtkdlSmQdIKg/SPDXRef-gnrtd5
Run 2: 4CzNPOvXfkKulJsGbgigQA/SPDXRef-gnrtd5
```

When tools use `spdxId` as the dictionary key for element comparison or impact analysis, every element appears as a different entity -- even when the two SBOMs describe the same software. In practice, 277 of 278 common elements in real-world SBOM pairs have different spdxIds but are logically identical.

The identity resolution algorithm solves this by matching elements on **what they represent** rather than their arbitrary identifiers.

## Overview

`spdx_identity` provides a standalone implementation of the tiered identity resolution algorithm. The public API consists of:

- **`IdentityResolver`** -- Resolves a single SPDX element to a stable `(identity_key, tier)` tuple. Constructor accepts optional `purl_normalizer` for dependency injection.
- **`resolve_sbom()`** -- Convenience function to resolve all elements in a parsed SBOM at once (elements without `spdxId` are skipped).
- **`PURLNormalizer`** -- Normalizes Package URL (PURL) identifiers for comparison.
- **`REFERENCE_FIELDS`** -- Frozen set of property names that contain spdxId references and must be excluded from content hashing.

## Tiered Resolution Algorithm

Each element is assigned an identity key from the highest available tier:

```
                  +---------------------------+
                  |  Extract element          |
                  +------------+--------------+
                               |
               +---------------v-----------------+
               | Has permanent ID?               |
               | (PURL, CPE, CVE, SWHID,         |
               |  gitoid)                        |
               +--------+----------+-------------+
                  yes   |          |  no
                        v          v
              +----------+  +---------------------+
              | Tier 1   |  | Has type-specific   |
              | perm::   |  | composite key?      |
              +----------+  +--------+------+-----+
                               yes   |      |  no
                                     v      v
                           +----------+  +----------+
                           | Tier 2   |  | Tier 3   |
                           | type::   |  | hash::   |
                           +----------+  +----------+
```

**Key principle:** Version is excluded from Tier 1 and Tier 2 identity keys. Tier 3 hashes the full non-reference payload, so version fields are included there if present.

### Tier 1: Permanent Identifiers

Permanent identifiers are external, cross-SBOM-stable identifiers. They are checked in priority order:

| Source | Property Path | Normalization | Version Stripping |
|--------|--------------|---------------|-------------------|
| Package URL (property) | `packageUrl` or `software_packageUrl` | `PURLNormalizer.normalize_purl()` | Strip `@version` and all qualifiers |
| Package URL (external ID) | `externalIdentifier[externalIdentifierType=packageUrl].identifier` | Same | Same |
| CPE 2.3 | `externalIdentifier[externalIdentifierType=cpe23].identifier` | Lowercase | Replace version + update fields with `*` |
| CPE 2.2 | `externalIdentifier[externalIdentifierType=cpe22].identifier` | Lowercase | Strip version component |
| CVE | `externalIdentifier[externalIdentifierType=cve].identifier` | Uppercase | N/A (version-less by nature) |
| SWHID | `externalIdentifier[externalIdentifierType=swhid].identifier` | As-is | N/A (content-addressable) |
| gitoid | `externalIdentifier[externalIdentifierType=gitoid].identifier` | As-is | N/A (content-addressable) |

**Key format:** `perm::<normalized_id>` (e.g., `perm::pkg:pypi/pyyaml`)

#### PURL Qualifier Stripping

**Design decision:** PURL qualifiers are **stripped** from identity keys, not preserved. While some qualifiers (e.g., `arch=amd64`) could be identity-distinguishing, others like SWID `tag_id` are per-run UUIDs that defeat matching:

```
pkg:swid/swidgroup/example@1.0?tag_id=2df9de35-0aff-4a86-ace6-f7dddd1ade4c
pkg:swid/swidgroup/example@1.0?tag_id=a9b25e30-4cc2-4b16-b47e-1d2f32e18c56
```

Stripping all qualifiers is the safe default. The version-free, qualifier-free PURL retains enough information to identify the logical package.

### Tier 2: Composite Keys

Type-specific keys built from identifying properties (version always excluded).

**Core Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `Agent`, `Person`, `Organization`, `SoftwareAgent` | `type::name` | May have duplicates (see Duplicate Key Resolution) |
| `Tool` | `type::name` | |
| `SpdxDocument` | `type::name` | Usually one per SBOM |
| `Bundle`, `Bom` | `type::name` | |
| `Annotation` | `type::annotationType::hash(statement)` | `subject` is a reference field, excluded |
| `IndividualElement` | `type::name` | For NoneElement, NoAssertionElement |

**Software Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `software_Package` | `type::name` | `name` is mandatory; version excluded |
| `software_File` | `type::name` | File path is typically unique |
| `software_Snippet` | `type::hash(byteRange,lineRange)` | Falls to Tier 3 if no range data |
| `software_Sbom` | `type::name` | |

**Security Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `security_Vulnerability` | `type::name` | `name` is typically the CVE ID |

**AI and Dataset Profiles:**

| Type | Key Components |
|------|---------------|
| `ai_AIPackage` | `type::name` |
| `dataset_DatasetPackage` | `type::name` |

**Build Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `build_Build` | `type::buildType::buildId` | `buildId` omitted from key if absent |

**SimpleLicensing Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `simplelicensing_LicenseExpression` | `type::licenseExpression` | The expression IS the identity |
| `simplelicensing_SimpleLicensingText` | Falls to Tier 3 | `licenseText` too large for key |

**ExpandedLicensing Profile:**

| Type | Key Components | Notes |
|------|---------------|-------|
| `expandedlicensing_ListedLicense` | `type::name` | |
| `expandedlicensing_IndividualLicensingInfo` | `type::name` | |
| `expandedlicensing_ListedLicenseException` | `type::name` | |
| All others (`CustomLicense`, `ConjunctiveLicenseSet`, etc.) | Fall to Tier 3 | Contain only reference fields or unbounded text |

**Generic fallback:** Any unlisted element type with a `name` property uses `type::name`. Elements without `name` fall to Tier 3.

### Tier 3: Content Hash

For elements without permanent identifiers or usable composite key properties:

1. Collect all non-reference, non-structural properties from the element
2. Serialize deterministically: `json.dumps(filtered_props, sort_keys=True, default=_json_default)` where sets/frozensets are converted to sorted string lists
3. Hash with SHA-256, truncated to 16 hex characters

**Key format:** `hash::<type>::<hex_digest>`

**Excluded from hash:** All reference fields (see below) plus `@type` and `@context`.

## Reference Field Exclusion

Reference fields contain spdxId values that are unstable across runs. They are excluded from content hashing and structural comparison:

`spdxId`, `@id`, `creationInfo`, `suppliedBy`, `originatedBy`, `from`, `to`, `element`, `rootElement`, `subject`, `snippetFromFile`, `assessedElement`, `member`, `subjectLicense`, `subjectExtendableLicense`, `subjectAddition`, `createdBy`, `createdUsing`

These are available as the `REFERENCE_FIELDS` constant.

## Post-Match Validation

`spdx_identity` exposes `IdentityResolver.validate_match(old_element, new_element)` for callers to reject false positives after key-based pairing. This check is not run automatically by `compute_identity_key()` or `resolve_sbom()`.

1. Compute the union of non-reference property names present in either element
2. Exclude `@type` and `@context` (structural, not semantic)
3. Count how many properties have different values
4. If **>70%** of comparable properties differ, reject the match

This prevents Tier 2/3 collisions (e.g., two unrelated packages that happen to share a name) from producing misleading results.

## PURL Normalization

The `PURLNormalizer` class provides Package URL normalization:

- **`normalize_purl(purl)`** -- Normalizes a PURL string: lowercases type, namespace, and name; sorts qualifiers alphabetically.
- **`are_purls_equivalent(purl1, purl2)`** -- Returns `True` if two PURLs are equivalent after normalization.
- **`extract_purl_components(purl)`** -- Parses a PURL into its component parts (scheme, type, namespace, name, version, qualifiers, subpath).

## Relationship Identity Keys

The `IdentityResolver` can also compute stable identity keys for SPDX relationships:

```python
resolver = IdentityResolver()
key = resolver.compute_relationship_identity_key(relationship_dict)
```

The key format is:

```text
rel::{type}::{from}::{relationshipType}::{to}::{scope}
```

- **`type`** -- The JSON-LD type of the relationship (e.g., `Relationship`, `LifecycleScopedRelationship`).
- **`from`** -- The source element identifier.
- **`relationshipType`** -- The SPDX relationship type (e.g., `DEPENDS_ON`, `CONTAINS`).
- **`to`** -- If scalar, used as-is. If list, values are sorted and encoded as bracketed pipe-delimited form: `[a|b|c]`.
- **`scope`** -- The lifecycle scope (if present, otherwise empty).

The list form of `to` is **sorted** for determinism: two relationships with the same targets in different orders produce the same identity key.

## Worked Examples

### Example 1: Package matched by PURL (Tier 1)

```python
from spdx_identity import IdentityResolver

resolver = IdentityResolver()

element = {
    "spdxId": "ABC/SPDXRef-gnrtd5",
    "type": "software_Package",
    "name": "pyyaml",
    "packageVersion": "6.0.1",
    "packageUrl": "pkg:pypi/pyyaml@6.0.1?tag_id=uuid-123",
}

key, tier = resolver.compute_identity_key(element)
# key = "perm::pkg:pypi/pyyaml"
# tier = 1
```

1. **Tier 1:** PURL `pkg:pypi/pyyaml@6.0.1?tag_id=uuid-123` -> strip version + qualifiers -> `pkg:pypi/pyyaml` -> normalize -> key: `perm::pkg:pypi/pyyaml`

### Example 2: Agent matched by composite key (Tier 2)

```python
element = {
    "spdxId": "ABC/SPDXRef-gnrtd1",
    "type": "Agent",
    "name": "syft",
    "creationInfo": "ABC/creationinfo-ref",
}

key, tier = resolver.compute_identity_key(element)
# key = "Agent::syft"
# tier = 2
```

1. **Tier 1:** No PURL, CPE, CVE, or SWHID -> skip
2. **Tier 2:** `Agent` is a name-keyed type -> key: `Agent::syft`

### Example 3: Bulk SBOM resolution

```python
from spdx_identity import resolve_sbom

elements = [
    {"spdxId": "id-1", "type": "software_Package", "name": "flask",
     "packageUrl": "pkg:pypi/flask@2.0"},
    {"spdxId": "id-2", "type": "Agent", "name": "syft"},
    {"spdxId": "id-3", "type": "simplelicensing_SimpleLicensingText",
     "licenseText": "...long text..."},
]

result = resolve_sbom(elements)
# {
#     "id-1": ("perm::pkg:pypi/flask", 1),
#     "id-2": ("Agent::syft", 2),
#     "id-3": ("hash::simplelicensing_SimpleLicensingText::a1b2c3d4e5f67890", 3),
# }
```

## Key Source Files

| File | Purpose |
|------|---------|
| `spdx_identity/resolver.py` | `IdentityResolver` class with all three tiers |
| `spdx_identity/purl_normalizer.py` | `PURLNormalizer` for PURL decomposition and normalization |
| `spdx_identity/constants.py` | `REFERENCE_FIELDS`, `PERM_ID_TYPES`, `VALIDATION_THRESHOLD` |
| `spdx_identity/__init__.py` | Public API exports and `resolve_sbom()` convenience function |
