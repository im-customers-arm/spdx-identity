"""Constants for SPDX element identity resolution."""

from __future__ import annotations

# Properties that contain spdxId references and must be excluded from
# content hashing and structural comparison.
REFERENCE_FIELDS: frozenset[str] = frozenset(
    {
        "spdxId",
        "@id",
        "creationInfo",
        "suppliedBy",
        "originatedBy",
        "from",
        "to",
        "element",
        "rootElement",
        "subject",
        "snippetFromFile",
        "assessedElement",
        "member",
        "subjectLicense",
        "subjectExtendableLicense",
        "subjectAddition",
        "createdBy",
        "createdUsing",
    }
)

# Permanent identifier types in priority order.
PERM_ID_TYPES: tuple[str, ...] = (
    "packageUrl",
    "cpe23",
    "cpe22",
    "cve",
    "swhid",
    "gitoid",
)

# Similarity threshold: reject matches where >70% of properties differ.
VALIDATION_THRESHOLD: float = 0.70
