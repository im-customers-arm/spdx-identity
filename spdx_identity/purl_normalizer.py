"""PURL (Package URL) normalizer for advanced package identification."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class PURLNormalizer:
    """Normalizes PURL (Package URL) identifiers for comparison."""

    def __init__(self) -> None:
        """Initialize the PURL normalizer."""
        self.logger = logging.getLogger(__name__)

    def normalize_purl(self, purl: str) -> str:
        """Normalize a PURL for comparison.

        Args:
            purl: Package URL string

        Returns:
            Normalized PURL string
        """
        if not purl or not isinstance(purl, str):
            return purl

        try:
            # Parse PURL manually: pkg:type/namespace/name@version?qualifiers#subpath
            if not purl.startswith("pkg:"):
                self.logger.warning(f"Invalid PURL: {purl}, expected to start with 'pkg:'")
                return purl

            # Remove the pkg: prefix
            purl_content = purl[4:]

            # Split by @ to separate version and qualifiers
            if "@" in purl_content:
                base_part, version_part = purl_content.split("@", 1)
            else:
                base_part = purl_content
                version_part = ""

            # Split version and qualifiers
            if "?" in version_part:
                version, qualifiers_part = version_part.split("?", 1)
            else:
                version = version_part
                qualifiers_part = ""

            # Parse qualifiers
            qualifiers: dict[str, str] = {}
            if qualifiers_part:
                for qualifier in qualifiers_part.split("&"):
                    if "=" in qualifier:
                        key, value = qualifier.split("=", 1)
                        qualifiers[key] = value

            # Parse the base part (type/namespace/name)
            parts = base_part.split("/")
            if len(parts) < 2:
                self.logger.warning(f"Invalid PURL format: {purl}")
                return purl

            package_type = parts[0].lower()
            # For PURLs like pkg:npm/example, the second part is the name, not namespace
            if len(parts) == 2:
                namespace = ""
                name = parts[1].lower()
                subpath = ""
            else:
                namespace = parts[1].lower() if len(parts) > 1 else ""
                name = parts[2].lower() if len(parts) > 2 else ""
                subpath = "/".join(parts[3:]) if len(parts) > 3 else ""

            # Reconstruct normalized PURL
            normalized_parts = ["pkg:", package_type]

            if namespace:
                normalized_parts.append(f"/{namespace}")
            if name:
                normalized_parts.append(f"/{name}")
            if subpath:
                normalized_parts.append(f"/{subpath}")

            if version:
                normalized_parts.append(f"@{version}")

            if qualifiers:
                sorted_qualifiers = []
                for key in sorted(qualifiers.keys()):
                    sorted_qualifiers.append(f"{key}={qualifiers[key]}")
                normalized_parts.append(f"?{'&'.join(sorted_qualifiers)}")

            normalized = "".join(normalized_parts)

            self.logger.debug(f"Normalized PURL: {purl} -> {normalized}")
            return normalized

        except Exception as e:
            self.logger.warning(f"Failed to normalize PURL '{purl}': {e}")
            return purl

    def are_purls_equivalent(self, purl1: str, purl2: str) -> bool:
        """Check if two PURLs are equivalent after normalization.

        Args:
            purl1: First PURL
            purl2: Second PURL

        Returns:
            True if PURLs are equivalent
        """
        if not purl1 or not purl2:
            return purl1 == purl2

        normalized1 = self.normalize_purl(purl1)
        normalized2 = self.normalize_purl(purl2)

        return normalized1 == normalized2

    def extract_purl_components(self, purl: str) -> dict[str, Any]:
        """Extract components from a PURL.

        Args:
            purl: Package URL string

        Returns:
            Dictionary with PURL components
        """
        if not purl or not isinstance(purl, str):
            return {}

        try:
            # Parse PURL manually: pkg:type/namespace/name@version?qualifiers#subpath
            if not purl.startswith("pkg:"):
                return {}

            # Remove the pkg: prefix
            purl_content = purl[4:]

            # Split by @ to separate version and qualifiers
            if "@" in purl_content:
                base_part, version_part = purl_content.split("@", 1)
            else:
                base_part = purl_content
                version_part = ""

            # Split version and qualifiers
            if "?" in version_part:
                version, qualifiers_part = version_part.split("?", 1)
            else:
                version = version_part
                qualifiers_part = ""

            # Parse qualifiers
            qualifiers: dict[str, str] = {}
            if qualifiers_part:
                for qualifier in qualifiers_part.split("&"):
                    if "=" in qualifier:
                        key, value = qualifier.split("=", 1)
                        qualifiers[key] = value

            # Parse the base part (type/namespace/name)
            parts = base_part.split("/")
            if len(parts) < 2:
                return {}

            package_type = parts[0]
            # For PURLs like pkg:npm/example, the second part is the name, not namespace
            if len(parts) == 2:
                namespace = ""
                name = parts[1]
                subpath = ""
            else:
                namespace = parts[1] if len(parts) > 1 else ""
                name = parts[2] if len(parts) > 2 else ""
                subpath = "/".join(parts[3:]) if len(parts) > 3 else ""

            components: dict[str, Any] = {
                "scheme": "pkg",
                "type": package_type,
                "namespace": namespace,
                "name": name,
                "version": version,
                "qualifiers": qualifiers,
                "subpath": subpath,
            }

            return components

        except Exception as e:
            self.logger.warning(f"Failed to extract PURL components from '{purl}': {e}")
            return {}
