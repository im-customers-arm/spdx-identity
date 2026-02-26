"""Comprehensive unit tests for IdentityResolver -- tiered identity resolution."""

from __future__ import annotations

import pytest

from spdx_identity import REFERENCE_FIELDS, IdentityResolver, PURLNormalizer, resolve_sbom
from spdx_identity.constants import PERM_ID_TYPES, VALIDATION_THRESHOLD


@pytest.fixture
def resolver() -> IdentityResolver:
    return IdentityResolver(PURLNormalizer())


# ======================================================================
# Tier 1 -- Permanent identifier extraction
# ======================================================================


class TestTier1PermanentId:
    """PURL, CPE, CVE, SWHID, gitoid extraction and version stripping."""

    def test_purl_from_package_url_property(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "pyyaml",
            "packageUrl": "pkg:pypi/pyyaml@6.0.1",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert key.startswith("perm::")
        # Version should be stripped
        assert "@" not in key
        assert "pyyaml" in key.lower()

    def test_purl_from_software_package_url_variant(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "requests",
            "software_packageUrl": "pkg:pypi/requests@2.31.0",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert "@" not in key

    def test_purl_version_stripping(self, resolver: IdentityResolver):
        """Same package different versions produce the same key."""
        elem_v1 = {
            "type": "software_Package",
            "name": "flask",
            "packageUrl": "pkg:pypi/flask@2.3.0",
        }
        elem_v2 = {
            "type": "software_Package",
            "name": "flask",
            "packageUrl": "pkg:pypi/flask@3.0.0",
        }
        key1, _ = resolver.compute_identity_key(elem_v1)
        key2, _ = resolver.compute_identity_key(elem_v2)
        assert key1 == key2

    def test_purl_qualifiers_stripped_for_identity(self, resolver: IdentityResolver):
        """Qualifiers are stripped because they are contextual, not identity-defining."""
        elem = {
            "type": "software_Package",
            "name": "numpy",
            "packageUrl": "pkg:pypi/numpy@1.24.0?os=linux",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert key == "perm::pkg:pypi/numpy"
        assert "os=linux" not in key

    def test_purl_from_external_identifier(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "lodash",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "packageUrl",
                    "identifier": "pkg:npm/lodash@4.17.21",
                }
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert "lodash" in key.lower()
        assert "@" not in key

    def test_cpe23_normalization_and_version_strip(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "openssl",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
                }
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert "perm::" in key
        # Version and update fields should be wildcarded
        assert "cpe:2.3:a:openssl:openssl:*:*:" in key

    def test_cpe23_different_versions_same_key(self, resolver: IdentityResolver):
        base = {
            "type": "software_Package",
            "name": "openssl",
        }
        elem1 = {
            **base,
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
                }
            ],
        }
        elem2 = {
            **base,
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:openssl:openssl:3.0.8:update1:*:*:*:*:*:*",
                }
            ],
        }
        assert resolver.compute_identity_key(elem1)[0] == resolver.compute_identity_key(elem2)[0]

    def test_cpe22_version_strip(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "curl",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe22",
                    "identifier": "cpe:/a:haxx:curl:7.88.0",
                }
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        # CPE 2.2: version component stripped
        assert "7.88.0" not in key
        assert "cpe:/a:haxx" in key

    def test_cve_identity(self, resolver: IdentityResolver):
        elem = {
            "type": "security_Vulnerability",
            "name": "CVE-2023-1234",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cve",
                    "identifier": "cve-2023-1234",
                }
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert key == "perm::CVE-2023-1234"

    def test_swhid_identity(self, resolver: IdentityResolver):
        swhid = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
        elem = {
            "type": "software_File",
            "name": "main.py",
            "externalIdentifier": [
                {"externalIdentifierType": "swhid", "identifier": swhid}
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert key == f"perm::{swhid}"

    def test_gitoid_identity(self, resolver: IdentityResolver):
        gitoid = "gitoid:blob:sha256:fee53a18d7ac20e3043be9b28133"
        elem = {
            "type": "software_File",
            "name": "lib.rs",
            "externalIdentifier": [
                {"externalIdentifierType": "gitoid", "identifier": gitoid}
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        assert key == f"perm::{gitoid}"

    def test_priority_ordering_purl_over_cpe(self, resolver: IdentityResolver):
        """packageUrl property takes priority over CPE in externalIdentifier."""
        elem = {
            "type": "software_Package",
            "name": "openssl",
            "packageUrl": "pkg:generic/openssl@3.0.8",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*",
                }
            ],
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 1
        # Should use PURL, not CPE
        assert key.startswith("perm::pkg:")

    def test_scoped_npm_packages_produce_distinct_keys(self, resolver: IdentityResolver):
        """Different @-scoped npm packages must NOT collide on identity key."""
        key1, _ = resolver.compute_identity_key({"packageUrl": "pkg:npm/@types/node@18.0.0"})
        key2, _ = resolver.compute_identity_key({"packageUrl": "pkg:npm/@babel/core@7.12.0"})
        assert key1 != key2
        assert "types" in key1 or "node" in key1
        assert "babel" in key2 or "core" in key2

    def test_ext_id_priority_purl_before_cpe(self, resolver: IdentityResolver):
        """Within externalIdentifier, packageUrl takes priority over cpe23."""
        elem = {
            "type": "software_Package",
            "name": "test",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
                },
                {
                    "externalIdentifierType": "packageUrl",
                    "identifier": "pkg:generic/test@1.0",
                },
            ],
        }
        key, _ = resolver.compute_identity_key(elem)
        assert key.startswith("perm::pkg:")


# ======================================================================
# Tier 2 -- Composite key generation
# ======================================================================


class TestTier2CompositeKey:
    """Composite key generation for various SPDX element types."""

    def test_software_package_by_name(self, resolver: IdentityResolver):
        elem = {"type": "software_Package", "name": "numpy"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "software_Package::numpy"

    def test_software_file_by_name(self, resolver: IdentityResolver):
        elem = {"type": "software_File", "name": "/usr/lib/libssl.so"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "software_File::/usr/lib/libssl.so"

    def test_agent_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Agent", "name": "NOASSERTION"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Agent::NOASSERTION"

    def test_person_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Person", "name": "Jane Doe"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Person::Jane Doe"

    def test_organization_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Organization", "name": "Acme Corp"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Organization::Acme Corp"

    def test_software_agent_by_name(self, resolver: IdentityResolver):
        elem = {"type": "SoftwareAgent", "name": "scanner-tool"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "SoftwareAgent::scanner-tool"

    def test_tool_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Tool", "name": "syft"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Tool::syft"

    def test_spdx_document_by_name(self, resolver: IdentityResolver):
        elem = {"type": "SpdxDocument", "name": "myapp-sbom"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "SpdxDocument::myapp-sbom"

    def test_bundle_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Bundle", "name": "release-bundle"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Bundle::release-bundle"

    def test_bom_by_name(self, resolver: IdentityResolver):
        elem = {"type": "Bom", "name": "my-bom"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "Bom::my-bom"

    def test_vulnerability_by_name(self, resolver: IdentityResolver):
        elem = {"type": "security_Vulnerability", "name": "CVE-2024-5678"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "security_Vulnerability::CVE-2024-5678"

    def test_ai_package_by_name(self, resolver: IdentityResolver):
        elem = {"type": "ai_AIPackage", "name": "gpt-4-model"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "ai_AIPackage::gpt-4-model"

    def test_dataset_package_by_name(self, resolver: IdentityResolver):
        elem = {"type": "dataset_DatasetPackage", "name": "imagenet-2012"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "dataset_DatasetPackage::imagenet-2012"

    def test_annotation_key(self, resolver: IdentityResolver):
        elem = {
            "type": "Annotation",
            "annotationType": "REVIEW",
            "statement": "Reviewed and approved.",
            "subject": "SPDXRef-Pkg1",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key.startswith("Annotation::REVIEW::")

    def test_annotation_different_statements(self, resolver: IdentityResolver):
        """Different statements produce different keys."""
        e1 = {"type": "Annotation", "annotationType": "REVIEW", "statement": "ok"}
        e2 = {"type": "Annotation", "annotationType": "REVIEW", "statement": "bad"}
        k1, _ = resolver.compute_identity_key(e1)
        k2, _ = resolver.compute_identity_key(e2)
        assert k1 != k2

    def test_snippet_with_range(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Snippet",
            "byteRange": {"startPointer": 0, "endPointer": 100},
            "lineRange": {"startPointer": 1, "endPointer": 10},
            "snippetFromFile": "SPDXRef-File1",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key.startswith("software_Snippet::")

    def test_snippet_without_range_falls_to_tier3(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Snippet",
            "snippetFromFile": "SPDXRef-File1",
        }
        _, tier = resolver.compute_identity_key(elem)
        assert tier == 3

    def test_build_with_build_id(self, resolver: IdentityResolver):
        elem = {
            "type": "build_Build",
            "buildType": "https://example.com/build",
            "buildId": "build-123",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "build_Build::https://example.com/build::build-123"

    def test_build_without_build_id(self, resolver: IdentityResolver):
        elem = {"type": "build_Build", "buildType": "https://example.com/build"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "build_Build::https://example.com/build"

    def test_license_expression(self, resolver: IdentityResolver):
        elem = {
            "type": "simplelicensing_LicenseExpression",
            "licenseExpression": "MIT OR Apache-2.0",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "simplelicensing_LicenseExpression::MIT OR Apache-2.0"

    def test_listed_license(self, resolver: IdentityResolver):
        elem = {"type": "expandedlicensing_ListedLicense", "name": "Apache-2.0"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "expandedlicensing_ListedLicense::Apache-2.0"

    def test_custom_license_falls_to_tier3(self, resolver: IdentityResolver):
        elem = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "Custom license text...",
        }
        _, tier = resolver.compute_identity_key(elem)
        assert tier == 3

    def test_conjunctive_license_set_falls_to_tier3(self, resolver: IdentityResolver):
        elem = {
            "type": "expandedlicensing_ConjunctiveLicenseSet",
            "member": ["SPDXRef-License1", "SPDXRef-License2"],
        }
        _, tier = resolver.compute_identity_key(elem)
        assert tier == 3

    def test_individual_element_by_name(self, resolver: IdentityResolver):
        elem = {"type": "IndividualElement", "name": "NoAssertionElement"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "IndividualElement::NoAssertionElement"

    def test_software_sbom_by_name(self, resolver: IdentityResolver):
        elem = {"type": "software_Sbom", "name": "app-sbom"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "software_Sbom::app-sbom"

    def test_generic_fallback_with_name(self, resolver: IdentityResolver):
        """Unknown type with name property gets a composite key."""
        elem = {"type": "FutureElementType", "name": "something"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "FutureElementType::something"

    def test_at_type_variant(self, resolver: IdentityResolver):
        """@type is used when type is absent."""
        elem = {"@type": "software_Package", "name": "requests"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2
        assert key == "software_Package::requests"

    def test_version_excluded_from_composite_key(self, resolver: IdentityResolver):
        """Version differences should not affect the key."""
        e1 = {"type": "software_Package", "name": "flask", "packageVersion": "2.0"}
        e2 = {"type": "software_Package", "name": "flask", "packageVersion": "3.0"}
        assert resolver.compute_identity_key(e1) == resolver.compute_identity_key(e2)


# ======================================================================
# Tier 3 -- Content hash
# ======================================================================


class TestTier3ContentHash:
    """Content hash for elements without permanent ID or composite key."""

    def test_nameless_element_gets_hash(self, resolver: IdentityResolver):
        elem = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "Proprietary license v1",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 3
        assert key.startswith("hash::expandedlicensing_CustomLicense::")

    def test_reference_fields_excluded_from_hash(self, resolver: IdentityResolver):
        """Changing only reference fields should not change the hash."""
        base = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "Some license",
        }
        e1 = {**base, "spdxId": "SPDXRef-A", "createdBy": ["SPDXRef-Agent1"]}
        e2 = {**base, "spdxId": "SPDXRef-B", "createdBy": ["SPDXRef-Agent2"]}
        k1, _ = resolver.compute_identity_key(e1)
        k2, _ = resolver.compute_identity_key(e2)
        assert k1 == k2

    def test_hash_stability_across_property_ordering(self, resolver: IdentityResolver):
        """JSON keys are sorted, so insertion order doesn't matter."""
        e1 = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "License text",
            "comment": "A comment",
        }
        # Same properties, different insertion order
        e2: dict = {}
        e2["comment"] = "A comment"
        e2["licenseText"] = "License text"
        e2["type"] = "expandedlicensing_CustomLicense"
        k1, _ = resolver.compute_identity_key(e1)
        k2, _ = resolver.compute_identity_key(e2)
        assert k1 == k2

    def test_different_content_different_hash(self, resolver: IdentityResolver):
        e1 = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "License A",
        }
        e2 = {
            "type": "expandedlicensing_CustomLicense",
            "licenseText": "License B",
        }
        k1, _ = resolver.compute_identity_key(e1)
        k2, _ = resolver.compute_identity_key(e2)
        assert k1 != k2

    def test_element_without_type_falls_to_hash(self, resolver: IdentityResolver):
        """Edge case: element with no type at all."""
        elem = {"description": "orphaned data"}
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 3
        assert key.startswith("hash::::")


# ======================================================================
# REFERENCE_FIELDS constant
# ======================================================================


class TestReferenceFields:
    """Verify the REFERENCE_FIELDS constant matches the plan."""

    def test_contains_all_planned_fields(self):
        expected = {
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
        assert REFERENCE_FIELDS == expected


# ======================================================================
# Post-match validation
# ======================================================================


class TestPostMatchValidation:
    """validate_match rejects when >70% of properties differ."""

    def test_identical_elements_valid(self, resolver: IdentityResolver):
        elem = {"type": "software_Package", "name": "x", "version": "1.0"}
        assert resolver.validate_match(elem, elem) is True

    def test_minor_difference_valid(self, resolver: IdentityResolver):
        old = {"type": "software_Package", "name": "x", "version": "1.0", "description": "a"}
        new = {"type": "software_Package", "name": "x", "version": "2.0", "description": "a"}
        assert resolver.validate_match(old, new) is True

    def test_mostly_different_rejected(self, resolver: IdentityResolver):
        """>70% of non-reference properties differ -> rejected."""
        old = {
            "type": "software_Package",
            "name": "totally-different-a",
            "packageVersion": "1.0",
            "description": "old desc",
            "comment": "old comment",
        }
        new = {
            "type": "software_Package",
            "name": "totally-different-b",
            "packageVersion": "9.0",
            "description": "new desc",
            "comment": "new comment",
        }
        # 4 out of 5 non-ref properties differ (name, version, desc, comment) = 80%
        assert resolver.validate_match(old, new) is False

    def test_reference_fields_excluded_from_validation(self, resolver: IdentityResolver):
        """Reference field differences don't count toward the threshold."""
        old = {
            "type": "software_Package",
            "name": "pkg",
            "spdxId": "old-id",
            "creationInfo": "old-info",
            "suppliedBy": "old-supplier",
        }
        new = {
            "type": "software_Package",
            "name": "pkg",
            "spdxId": "new-id",
            "creationInfo": "new-info",
            "suppliedBy": "new-supplier",
        }
        # Only non-ref props: type and name -- both match
        assert resolver.validate_match(old, new) is True

    def test_empty_elements_valid(self, resolver: IdentityResolver):
        assert resolver.validate_match({}, {}) is True

    def test_validation_threshold_boundary(self, resolver: IdentityResolver):
        """Exactly at 70% -- should still be accepted (> not >=)."""
        # 7 out of 10 non-ref properties differ = 70% exactly
        old = {f"p{i}": f"old{i}" for i in range(10)}
        new = {f"p{i}": f"new{i}" if i < 7 else f"old{i}" for i in range(10)}
        assert resolver.validate_match(old, new) is True  # 70% is not > 70%


# ======================================================================
# Relationship identity key
# ======================================================================


class TestRelationshipIdentityKey:
    """compute_relationship_identity_key tests."""

    def test_basic_relationship_key(self, resolver: IdentityResolver):
        rel = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
        }
        key = resolver.compute_relationship_identity_key(rel)
        assert key == "rel::Relationship::SPDXRef-A::DEPENDS_ON::SPDXRef-B::"

    def test_relationship_with_at_type(self, resolver: IdentityResolver):
        rel = {
            "@type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "CONTAINS",
        }
        key = resolver.compute_relationship_identity_key(rel)
        assert key == "rel::Relationship::SPDXRef-A::CONTAINS::SPDXRef-B::"

    def test_relationship_with_scope(self, resolver: IdentityResolver):
        rel = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
            "scope": "runtime",
        }
        key = resolver.compute_relationship_identity_key(rel)
        assert key == "rel::Relationship::SPDXRef-A::DEPENDS_ON::SPDXRef-B::runtime"

    def test_relationship_to_list_sorted(self, resolver: IdentityResolver):
        rel = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": ["SPDXRef-C", "SPDXRef-B"],
            "relationshipType": "CONTAINS",
        }
        key = resolver.compute_relationship_identity_key(rel)
        # 'to' list should be sorted
        assert "SPDXRef-B|SPDXRef-C" in key

    def test_relationship_defaults(self, resolver: IdentityResolver):
        """Missing fields get empty string defaults."""
        rel = {}
        key = resolver.compute_relationship_identity_key(rel)
        assert key == "rel::Relationship::::::::"

    def test_same_relationship_same_key(self, resolver: IdentityResolver):
        """Two identical relationships produce the same key."""
        rel1 = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
        }
        rel2 = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
        }
        assert resolver.compute_relationship_identity_key(rel1) == resolver.compute_relationship_identity_key(rel2)

    def test_different_relationship_type_different_key(self, resolver: IdentityResolver):
        rel1 = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
        }
        rel2 = {
            "type": "Relationship",
            "from": "SPDXRef-A",
            "to": "SPDXRef-B",
            "relationshipType": "CONTAINS",
        }
        assert resolver.compute_relationship_identity_key(rel1) != resolver.compute_relationship_identity_key(rel2)


# ======================================================================
# Constants
# ======================================================================


class TestConstants:
    """Verify exported constants."""

    def test_perm_id_types(self):
        assert PERM_ID_TYPES == ("packageUrl", "cpe23", "cpe22", "cve", "swhid", "gitoid")

    def test_validation_threshold(self):
        assert VALIDATION_THRESHOLD == 0.70


# ======================================================================
# resolve_sbom() convenience function
# ======================================================================


class TestResolveSbom:
    """Tests for the resolve_sbom convenience function."""

    def test_resolve_sbom_basic(self):
        elements = [
            {"spdxId": "SPDXRef-A", "type": "software_Package", "name": "pkg-a"},
            {"spdxId": "SPDXRef-B", "type": "software_Package", "name": "pkg-b"},
        ]
        result = resolve_sbom(elements)
        assert "SPDXRef-A" in result
        assert "SPDXRef-B" in result
        key_a, tier_a = result["SPDXRef-A"]
        key_b, tier_b = result["SPDXRef-B"]
        assert tier_a == 2
        assert tier_b == 2
        assert key_a == "software_Package::pkg-a"
        assert key_b == "software_Package::pkg-b"

    def test_resolve_sbom_with_purl(self):
        elements = [
            {
                "spdxId": "SPDXRef-Flask",
                "type": "software_Package",
                "name": "flask",
                "packageUrl": "pkg:pypi/flask@2.3.0",
            },
        ]
        result = resolve_sbom(elements)
        key, tier = result["SPDXRef-Flask"]
        assert tier == 1
        assert key == "perm::pkg:pypi/flask"

    def test_resolve_sbom_empty(self):
        result = resolve_sbom([])
        assert result == {}

    def test_resolve_sbom_skips_elements_without_spdx_id(self):
        """Elements without spdxId should be skipped, not raise KeyError."""
        result = resolve_sbom([
            {"spdxId": "SPDXRef-A", "type": "software_Package", "name": "a"},
            {"type": "software_Package", "name": "no-id"},  # missing spdxId
        ])
        assert len(result) == 1
        assert "SPDXRef-A" in result


# ======================================================================
# Edge cases
# ======================================================================


class TestEdgeCases:
    """Various edge cases and robustness checks."""

    def test_non_dict_external_identifiers_ignored(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "test",
            "externalIdentifier": ["not-a-dict"],
        }
        key, tier = resolver.compute_identity_key(elem)
        # Should fall through to Tier 2
        assert tier == 2

    def test_external_identifier_not_list(self, resolver: IdentityResolver):
        elem = {
            "type": "software_Package",
            "name": "test",
            "externalIdentifier": "invalid",
        }
        key, tier = resolver.compute_identity_key(elem)
        assert tier == 2

    def test_resolver_without_purl_normalizer(self):
        """Default constructor creates its own PURLNormalizer."""
        r = IdentityResolver()
        elem = {
            "type": "software_Package",
            "name": "test",
            "packageUrl": "pkg:pypi/test@1.0",
        }
        key, tier = r.compute_identity_key(elem)
        assert tier == 1

    def test_no_type_no_name_falls_to_tier3(self, resolver: IdentityResolver):
        elem = {"description": "orphaned"}
        _, tier = resolver.compute_identity_key(elem)
        assert tier == 3
