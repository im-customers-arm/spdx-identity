"""Tiered identity resolution for SPDX 3.0.1 elements.

Resolves stable natural keys from nondeterministic spdxIds using a
three-tier identity strategy:

- Tier 1: Permanent identifiers (PURL, CPE, CVE, SWHID, gitoid)
- Tier 2: Composite keys (type + type-specific identifying properties)
- Tier 3: Content hash (SHA-256 of non-reference properties)

Elements matched by any tier undergo post-match validation to reject
false positives (>70% property divergence).
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from spdx_identity.constants import PERM_ID_TYPES, REFERENCE_FIELDS, VALIDATION_THRESHOLD
from spdx_identity.purl_normalizer import PURLNormalizer

logger = logging.getLogger(__name__)


class IdentityResolver:
    """Resolve stable identity keys for SPDX 3.0.1 elements."""

    def __init__(self, purl_normalizer: PURLNormalizer | None = None) -> None:
        self._purl = purl_normalizer or PURLNormalizer()
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Identity key computation
    # ------------------------------------------------------------------

    def compute_identity_key(self, element: dict) -> tuple[str, int]:
        """Return ``(identity_key, tier)`` for *element*.

        Tries Tier 1 -> Tier 2 -> Tier 3 in order.
        """
        perm = self._extract_permanent_id(element)
        if perm is not None:
            return perm, 1

        composite = self._compute_composite_key(element)
        if composite is not None:
            return composite, 2

        return self._compute_content_hash(element), 3

    # ------------------------------------------------------------------
    # Tier 1: Permanent identifiers
    # ------------------------------------------------------------------

    def _extract_permanent_id(self, element: dict) -> str | None:
        """Extract the highest-priority permanent identifier, version-stripped."""
        # Direct packageUrl property (highest priority)
        purl = element.get("packageUrl") or element.get("software_packageUrl")
        if purl and isinstance(purl, str):
            stripped = self._strip_purl_version(purl)
            normalized = self._purl.normalize_purl(stripped)
            return f"perm::{normalized}"

        # External identifiers
        ext_ids = element.get("externalIdentifier", [])
        if not isinstance(ext_ids, list):
            return None

        for id_type in PERM_ID_TYPES:
            for ext_id in ext_ids:
                if not isinstance(ext_id, dict):
                    continue
                eid_type = ext_id.get("externalIdentifierType", "")
                identifier = ext_id.get("identifier", "")
                if not identifier or not isinstance(identifier, str):
                    continue
                if eid_type == id_type:
                    return self._normalize_permanent_id(id_type, identifier)

        return None

    def _normalize_permanent_id(self, id_type: str, identifier: str) -> str:
        """Normalize a permanent identifier by type."""
        if id_type == "packageUrl":
            stripped = self._strip_purl_version(identifier)
            return f"perm::{self._purl.normalize_purl(stripped)}"
        if id_type in ("cpe23", "cpe22"):
            return f"perm::{self._strip_cpe_version(identifier)}"
        if id_type == "cve":
            return f"perm::{identifier.upper()}"
        # swhid, gitoid -- content-addressable, use as-is
        return f"perm::{identifier}"

    def _strip_purl_version(self, purl: str) -> str:
        """Strip the version segment and qualifiers from a PURL.

        For identity matching, both version and qualifiers are stripped because
        qualifiers like ``tag_id`` (SWID) are per-run identifiers, and others
        like ``repository_url`` are contextual rather than identity-defining.
        """
        components = self._purl.extract_purl_components(purl)
        if not components:
            return purl

        # Reconstruct without version or qualifiers
        parts = [f"pkg:{components['type']}"]
        if components.get("namespace"):
            parts.append(f"/{components['namespace']}")
        parts.append(f"/{components['name']}")
        if components.get("subpath"):
            parts.append(f"/{components['subpath']}")
        return "".join(parts)

    def _strip_cpe_version(self, cpe: str) -> str:
        """Strip the version field from a CPE string."""
        cpe_lower = cpe.lower()
        if cpe_lower.startswith("cpe:2.3:"):
            # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
            parts = cpe_lower.split(":")
            if len(parts) >= 6:
                parts[5] = "*"  # version field
                if len(parts) >= 7:
                    parts[6] = "*"  # update field
                return ":".join(parts)
            return cpe_lower
        if cpe_lower.startswith("cpe:/"):
            # CPE 2.2 format: cpe:/part:vendor:product:version
            parts = cpe_lower.split(":")
            if len(parts) >= 4:
                return ":".join(parts[:3])
            return cpe_lower
        return cpe_lower

    # ------------------------------------------------------------------
    # Tier 2: Composite keys
    # ------------------------------------------------------------------

    def _compute_composite_key(self, element: dict) -> str | None:
        """Build a type-specific composite key (version excluded)."""
        elem_type = element.get("type") or element.get("@type", "")
        if not elem_type:
            return None

        # --- Types keyed by type::name ---
        name = element.get("name")
        name_keyed_types = {
            "Agent",
            "Person",
            "Organization",
            "SoftwareAgent",
            "Tool",
            "SpdxDocument",
            "Bundle",
            "Bom",
            "IndividualElement",
            "software_Package",
            "software_File",
            "software_Sbom",
            "security_Vulnerability",
            "ai_AIPackage",
            "dataset_DatasetPackage",
            "expandedlicensing_ListedLicense",
            "expandedlicensing_IndividualLicensingInfo",
            "expandedlicensing_ListedLicenseException",
        }
        if elem_type in name_keyed_types and name:
            return f"{elem_type}::{name}"

        # --- Annotation: type::annotationType::content_hash(statement) ---
        if elem_type == "Annotation":
            ann_type = element.get("annotationType", "")
            statement = element.get("statement", "")
            stmt_hash = self._short_hash(statement)
            return f"Annotation::{ann_type}::{stmt_hash}"

        # --- software_Snippet: type::content_hash(byteRange,lineRange) ---
        if elem_type == "software_Snippet":
            byte_range = element.get("byteRange")
            line_range = element.get("lineRange")
            if byte_range or line_range:
                range_data = json.dumps(
                    {"byteRange": byte_range, "lineRange": line_range},
                    sort_keys=True,
                )
                return f"software_Snippet::{self._short_hash(range_data)}"
            return None  # Fall to Tier 3

        # --- build_Build: type::buildType::buildId ---
        if elem_type == "build_Build":
            build_type = element.get("buildType", "")
            build_id = element.get("buildId")
            key_parts = [f"build_Build::{build_type}"]
            if build_id:
                key_parts.append(f"::{build_id}")
            return "".join(key_parts)

        # --- simplelicensing_LicenseExpression ---
        if elem_type == "simplelicensing_LicenseExpression":
            expr = element.get("licenseExpression", "")
            if expr:
                return f"simplelicensing_LicenseExpression::{expr}"
            return None

        # --- Types that always fall to Tier 3 ---
        tier3_types = {
            "simplelicensing_SimpleLicensingText",
            "expandedlicensing_CustomLicense",
            "expandedlicensing_ConjunctiveLicenseSet",
            "expandedlicensing_DisjunctiveLicenseSet",
            "expandedlicensing_OrLaterOperator",
            "expandedlicensing_WithAdditionOperator",
            "expandedlicensing_CustomLicenseAddition",
        }
        if elem_type in tier3_types:
            return None

        # --- Generic fallback: any element with a name ---
        if name:
            return f"{elem_type}::{name}"

        return None

    # ------------------------------------------------------------------
    # Tier 3: Content hash
    # ------------------------------------------------------------------

    def _compute_content_hash(self, element: dict) -> str:
        """SHA-256 hash of non-reference properties, truncated to 16 hex chars."""
        elem_type = element.get("type") or element.get("@type", "")
        filtered = {
            k: v
            for k, v in element.items()
            if k not in REFERENCE_FIELDS and k not in ("@type", "@context")
        }
        digest = self._short_hash(json.dumps(filtered, sort_keys=True, default=str))
        return f"hash::{elem_type}::{digest}"

    # ------------------------------------------------------------------
    # Post-match validation
    # ------------------------------------------------------------------

    def validate_match(self, old_element: dict, new_element: dict) -> bool:
        """Return False if >70% of comparable non-reference properties differ."""
        comparable = set(old_element) | set(new_element)
        comparable -= REFERENCE_FIELDS
        # Exclude JSON-LD structural keys that aren't meaningful for comparison
        comparable -= {"@type", "@context"}

        if not comparable:
            return True

        differing = 0
        for prop in comparable:
            old_val = old_element.get(prop)
            new_val = new_element.get(prop)
            if old_val != new_val:
                differing += 1

        ratio = differing / len(comparable)
        if ratio > VALIDATION_THRESHOLD:
            self.logger.debug(
                "Rejected match: %.0f%% of %d properties differ (threshold %.0f%%)",
                ratio * 100,
                len(comparable),
                VALIDATION_THRESHOLD * 100,
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Relationship identity
    # ------------------------------------------------------------------

    def compute_relationship_identity_key(self, relationship: dict) -> str:
        """Compute a stable identity key for a relationship.

        Uses the structural tuple (type, from, to, relationshipType, scope)
        normalized into a deterministic string key.
        """
        rel_type = relationship.get("@type") or relationship.get("type", "Relationship")
        from_elem = relationship.get("from", "")
        to_field = relationship.get("to", "")
        relationship_type = relationship.get("relationshipType", "")
        scope = relationship.get("scope", "")

        # Normalize 'to' for deterministic key
        if isinstance(to_field, list):
            to_normalized = "|".join(sorted(str(t) for t in to_field))
        else:
            to_normalized = str(to_field)

        return f"rel::{rel_type}::{from_elem}::{relationship_type}::{to_normalized}::{scope}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _short_hash(data: str) -> str:
        """SHA-256 truncated to 16 hex characters."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
