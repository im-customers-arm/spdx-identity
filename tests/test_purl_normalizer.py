"""Tests for PURLNormalizer."""

from __future__ import annotations

import pytest

from spdx_identity.purl_normalizer import PURLNormalizer


class TestPURLNormalizerInit:
    """Tests for PURLNormalizer initialization."""

    def test_init_creates_normalizer(self) -> None:
        """Test PURLNormalizer initialization."""
        normalizer = PURLNormalizer()
        assert normalizer is not None
        assert normalizer.logger is not None


class TestNormalizePurl:
    """Tests for normalize_purl method."""

    @pytest.fixture
    def normalizer(self) -> PURLNormalizer:
        """Create a PURLNormalizer instance."""
        return PURLNormalizer()

    def test_normalize_simple_purl(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing simple PURL."""
        purl = "pkg:npm/lodash"
        result = normalizer.normalize_purl(purl)
        assert result is not None
        assert "npm" in result
        assert "lodash" in result

    def test_normalize_purl_with_namespace(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL with namespace."""
        purl = "pkg:npm/@types/node"
        result = normalizer.normalize_purl(purl)
        assert result is not None
        assert "npm" in result.lower()

    def test_normalize_purl_with_version(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL with version."""
        purl = "pkg:npm/lodash@4.17.21"
        result = normalizer.normalize_purl(purl)
        assert "@4.17.21" in result

    def test_normalize_purl_with_qualifiers(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL with qualifiers."""
        purl = "pkg:npm/lodash@4.17.21?arch=arm64&os=linux"
        result = normalizer.normalize_purl(purl)
        assert "arch=arm64" in result
        assert "os=linux" in result

    def test_normalize_purl_qualifiers_sorted(self, normalizer: PURLNormalizer) -> None:
        """Test qualifiers are sorted alphabetically."""
        purl1 = "pkg:npm/lodash@4.17.21?os=linux&arch=arm64"
        purl2 = "pkg:npm/lodash@4.17.21?arch=arm64&os=linux"
        result1 = normalizer.normalize_purl(purl1)
        result2 = normalizer.normalize_purl(purl2)
        # Both should produce same normalized form with sorted qualifiers
        assert result1 == result2

    def test_normalize_purl_with_subpath(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL with subpath (multiple path parts)."""
        purl = "pkg:maven/org/example/project/src/main"
        result = normalizer.normalize_purl(purl)
        assert result is not None

    def test_normalize_empty_string(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing empty string returns empty string."""
        result = normalizer.normalize_purl("")
        assert result == ""

    def test_normalize_none(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing None returns None."""
        result = normalizer.normalize_purl(None)
        assert result is None

    def test_normalize_non_string(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing non-string returns original value."""
        result = normalizer.normalize_purl(123)
        assert result == 123

    def test_normalize_invalid_purl_no_pkg(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL without pkg: prefix."""
        purl = "npm/lodash"  # Missing pkg:
        result = normalizer.normalize_purl(purl)
        assert result == purl  # Returns original on invalid

    def test_normalize_invalid_purl_single_part(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL with single part (invalid format)."""
        purl = "pkg:npm"  # Missing name part
        result = normalizer.normalize_purl(purl)
        assert result == purl  # Returns original on invalid format

    def test_normalize_purl_without_version(self, normalizer: PURLNormalizer) -> None:
        """Test normalizing PURL without @ version."""
        purl = "pkg:npm/lodash"  # No version
        result = normalizer.normalize_purl(purl)
        assert "@" not in result  # No version in output

    def test_normalize_purl_case_normalization(self, normalizer: PURLNormalizer) -> None:
        """Test PURL type and namespace are lowercased."""
        purl = "pkg:NPM/LODASH"
        result = normalizer.normalize_purl(purl)
        assert "npm" in result  # Type should be lowercase
        assert "lodash" in result  # Name should be lowercase


class TestArePurlsEquivalent:
    """Tests for are_purls_equivalent method."""

    @pytest.fixture
    def normalizer(self) -> PURLNormalizer:
        """Create a PURLNormalizer instance."""
        return PURLNormalizer()

    def test_equivalent_same_purl(self, normalizer: PURLNormalizer) -> None:
        """Test equivalent PURLs are detected."""
        purl = "pkg:npm/lodash@4.17.21"
        assert normalizer.are_purls_equivalent(purl, purl)

    def test_equivalent_different_qualifier_order(self, normalizer: PURLNormalizer) -> None:
        """Test PURLs with different qualifier order are equivalent."""
        purl1 = "pkg:npm/lodash@4.17.21?os=linux&arch=arm64"
        purl2 = "pkg:npm/lodash@4.17.21?arch=arm64&os=linux"
        assert normalizer.are_purls_equivalent(purl1, purl2)

    def test_not_equivalent_different_version(self, normalizer: PURLNormalizer) -> None:
        """Test PURLs with different versions are not equivalent."""
        purl1 = "pkg:npm/lodash@4.17.21"
        purl2 = "pkg:npm/lodash@4.17.20"
        assert not normalizer.are_purls_equivalent(purl1, purl2)

    def test_equivalent_empty_both(self, normalizer: PURLNormalizer) -> None:
        """Test empty PURLs are equivalent."""
        assert normalizer.are_purls_equivalent("", "")

    def test_equivalent_none_both(self, normalizer: PURLNormalizer) -> None:
        """Test None PURLs are equivalent."""
        assert normalizer.are_purls_equivalent(None, None)

    def test_not_equivalent_empty_and_value(self, normalizer: PURLNormalizer) -> None:
        """Test empty and non-empty PURLs are not equivalent."""
        assert not normalizer.are_purls_equivalent("", "pkg:npm/lodash")
        assert not normalizer.are_purls_equivalent("pkg:npm/lodash", "")


class TestExtractPurlComponents:
    """Tests for extract_purl_components method."""

    @pytest.fixture
    def normalizer(self) -> PURLNormalizer:
        """Create a PURLNormalizer instance."""
        return PURLNormalizer()

    def test_extract_simple_purl(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from simple PURL."""
        purl = "pkg:npm/lodash"
        components = normalizer.extract_purl_components(purl)
        assert components["scheme"] == "pkg"
        assert components["type"] == "npm"
        assert components["name"] == "lodash"

    def test_extract_purl_with_namespace(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL with namespace."""
        purl = "pkg:npm/babel/core"
        components = normalizer.extract_purl_components(purl)
        assert components["scheme"] == "pkg"
        assert components["type"] == "npm"
        assert components["namespace"] == "babel"
        assert components["name"] == "core"

    def test_extract_purl_with_version(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL with version."""
        purl = "pkg:npm/lodash@4.17.21"
        components = normalizer.extract_purl_components(purl)
        assert components["version"] == "4.17.21"

    def test_extract_purl_with_qualifiers(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL with qualifiers."""
        purl = "pkg:npm/lodash@4.17.21?arch=arm64&os=linux"
        components = normalizer.extract_purl_components(purl)
        assert components["qualifiers"] == {"arch": "arm64", "os": "linux"}

    def test_extract_purl_with_subpath(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL with subpath."""
        purl = "pkg:maven/org/example/project/src"
        components = normalizer.extract_purl_components(purl)
        assert components["subpath"] == "project/src"

    def test_extract_purl_without_version(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL without version."""
        purl = "pkg:npm/lodash"
        components = normalizer.extract_purl_components(purl)
        assert components["version"] == ""

    def test_extract_purl_without_qualifiers(self, normalizer: PURLNormalizer) -> None:
        """Test extracting components from PURL without qualifiers."""
        purl = "pkg:npm/lodash@4.17.21"
        components = normalizer.extract_purl_components(purl)
        assert components["qualifiers"] == {}

    def test_extract_empty_string(self, normalizer: PURLNormalizer) -> None:
        """Test extracting from empty string returns empty dict."""
        result = normalizer.extract_purl_components("")
        assert result == {}

    def test_extract_none(self, normalizer: PURLNormalizer) -> None:
        """Test extracting from None returns empty dict."""
        result = normalizer.extract_purl_components(None)
        assert result == {}

    def test_extract_non_string(self, normalizer: PURLNormalizer) -> None:
        """Test extracting from non-string returns empty dict."""
        result = normalizer.extract_purl_components(123)
        assert result == {}

    def test_extract_invalid_purl_no_pkg(self, normalizer: PURLNormalizer) -> None:
        """Test extracting from PURL without pkg: prefix."""
        purl = "npm/lodash"
        result = normalizer.extract_purl_components(purl)
        assert result == {}

    def test_extract_invalid_purl_single_part(self, normalizer: PURLNormalizer) -> None:
        """Test extracting from PURL with single part."""
        purl = "pkg:npm"
        result = normalizer.extract_purl_components(purl)
        assert result == {}

    def test_extract_purl_all_components(self, normalizer: PURLNormalizer) -> None:
        """Test extracting all components from full PURL."""
        purl = "pkg:maven/org/apache/commons@1.0?type=jar"
        components = normalizer.extract_purl_components(purl)
        assert components["scheme"] == "pkg"
        assert components["type"] == "maven"
        assert components["namespace"] == "org"
        assert components["name"] == "apache"
        assert components["version"] == "1.0"
        assert components["qualifiers"] == {"type": "jar"}


class TestPURLEdgeCases:
    """Edge case tests for PURLNormalizer."""

    @pytest.fixture
    def normalizer(self) -> PURLNormalizer:
        """Create a PURLNormalizer instance."""
        return PURLNormalizer()

    def test_purl_with_special_characters_in_version(self, normalizer: PURLNormalizer) -> None:
        """Test PURL with special characters in version."""
        purl = "pkg:npm/lodash@4.17.21-beta.1"
        result = normalizer.normalize_purl(purl)
        assert "4.17.21-beta.1" in result

    def test_purl_with_empty_qualifier_value(self, normalizer: PURLNormalizer) -> None:
        """Test PURL with qualifier that has no value (edge case)."""
        purl = "pkg:npm/lodash@4.17.21?arch="
        result = normalizer.normalize_purl(purl)
        assert result is not None

    def test_maven_purl_with_group_id(self, normalizer: PURLNormalizer) -> None:
        """Test Maven PURL with group ID."""
        purl = "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
        result = normalizer.normalize_purl(purl)
        assert "maven" in result

    def test_pypi_purl(self, normalizer: PURLNormalizer) -> None:
        """Test PyPI PURL normalization."""
        purl = "pkg:pypi/requests@2.28.0"
        result = normalizer.normalize_purl(purl)
        assert "pypi" in result
        assert "requests" in result

    def test_docker_purl(self, normalizer: PURLNormalizer) -> None:
        """Test Docker PURL normalization."""
        purl = "pkg:docker/alpine@3.16"
        result = normalizer.normalize_purl(purl)
        assert "docker" in result
        assert "alpine" in result
