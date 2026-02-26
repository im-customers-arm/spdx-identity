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

    def _parse_purl(self, purl: str) -> dict[str, Any] | None:
        """Parse a PURL into its components.

        Follows the PURL spec grammar:
        ``pkg:type/namespace/name@version?qualifiers#subpath``

        Returns:
            Dictionary with parsed components, or None on invalid input.
        """
        if not purl or not isinstance(purl, str):
            return None
        if not purl.startswith("pkg:"):
            return None

        purl_content = purl[4:]

        # Step 1: Strip #subpath from the end
        subpath = ""
        if "#" in purl_content:
            purl_content, subpath = purl_content.rsplit("#", 1)

        # Step 2: Strip ?qualifiers from the end
        qualifiers_str = ""
        if "?" in purl_content:
            purl_content, qualifiers_str = purl_content.rsplit("?", 1)

        # Step 3: Parse qualifiers
        qualifiers: dict[str, str] = {}
        if qualifiers_str:
            for qualifier in qualifiers_str.split("&"):
                if "=" in qualifier:
                    key, value = qualifier.split("=", 1)
                    qualifiers[key] = value

        # Step 4: Split into path segments
        parts = purl_content.split("/")
        if len(parts) < 2:
            return None

        package_type = parts[0]

        # Step 5: Extract @version from the last segment only
        last_segment = parts[-1]
        version = ""
        if "@" in last_segment:
            last_segment, version = last_segment.rsplit("@", 1)
            parts[-1] = last_segment

        # Step 6: Parse namespace and name
        if len(parts) == 2:
            namespace = ""
            name = parts[1]
        else:
            namespace = "/".join(parts[1:-1])
            name = parts[-1]

        return {
            "scheme": "pkg",
            "type": package_type,
            "namespace": namespace,
            "name": name,
            "version": version,
            "qualifiers": qualifiers,
            "subpath": subpath,
        }

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
            components = self._parse_purl(purl)
            if components is None:
                self.logger.warning(f"Invalid PURL: {purl}")
                return purl

            package_type = components["type"].lower()
            namespace = components["namespace"].lower()
            name = components["name"].lower()
            version = components["version"]
            qualifiers = components["qualifiers"]
            subpath = components["subpath"]

            # Reconstruct normalized PURL in spec order
            normalized_parts = ["pkg:", package_type]

            if namespace:
                normalized_parts.append(f"/{namespace}")
            if name:
                normalized_parts.append(f"/{name}")

            if version:
                normalized_parts.append(f"@{version}")

            if qualifiers:
                sorted_qualifiers = []
                for key in sorted(qualifiers.keys()):
                    sorted_qualifiers.append(f"{key}={qualifiers[key]}")
                normalized_parts.append(f"?{'&'.join(sorted_qualifiers)}")

            if subpath:
                normalized_parts.append(f"#{subpath}")

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
            Dictionary with PURL components (original case preserved)
        """
        try:
            components = self._parse_purl(purl)
            if components is None:
                return {}
            return components
        except Exception as e:
            self.logger.warning(f"Failed to extract PURL components from '{purl}': {e}")
            return {}
