"""SPDX element identity resolution -- stable natural keys from nondeterministic spdxIds."""

from __future__ import annotations

import logging

from spdx_identity.constants import REFERENCE_FIELDS
from spdx_identity.purl_normalizer import PURLNormalizer
from spdx_identity.resolver import IdentityResolver

logger = logging.getLogger(__name__)

__all__ = [
    "IdentityResolver",
    "PURLNormalizer",
    "REFERENCE_FIELDS",
    "resolve_sbom",
]


def resolve_sbom(elements: list[dict]) -> dict[str, tuple[str, int]]:
    """Resolve all elements in a parsed SBOM.

    Args:
        elements: List of SPDX element dicts, each containing an ``spdxId`` key.

    Returns:
        Mapping of ``{spdx_id: (identity_key, tier)}`` for every element.
    """
    resolver = IdentityResolver()
    result = {}
    for elem in elements:
        spdx_id = elem.get("spdxId")
        if spdx_id is None:
            logger.warning("Skipping element without spdxId: %s", elem.get("@type", "<unknown>"))
            continue
        result[spdx_id] = resolver.compute_identity_key(elem)
    return result
