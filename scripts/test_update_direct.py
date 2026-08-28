#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import ipaddress
import sys
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("update_direct.py")
SPEC = importlib.util.spec_from_file_location("update_direct", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
update_direct = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = update_direct
SPEC.loader.exec_module(update_direct)


class DomainDifferenceTests(unittest.TestCase):
    def test_domain_set_preserves_exact_and_suffix_semantics(self) -> None:
        domains, networks = update_direct.parse_rules(
            "example.com\n.example.org\n*.legacy.example.net\n",
            source_name="domain-set",
            plain_domain_set=True,
        )

        self.assertEqual(
            domains,
            {
                update_direct.DomainRule("DOMAIN", "example.com"),
                update_direct.DomainRule("DOMAIN-SUFFIX", "example.org"),
                update_direct.DomainRule("DOMAIN-SUFFIX", "legacy.example.net"),
            },
        )
        self.assertEqual(networks, [])

    def test_loyalsoldier_direct_domain_set_is_an_upstream(self) -> None:
        source = next(
            source
            for source in update_direct.UPSTREAM_SOURCES
            if source.name == "loyalsoldier-direct-domain-set"
        )

        self.assertTrue(source.plain_domain_set)
        self.assertEqual(
            source.location,
            "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt",
        )

    def test_child_exclusion_does_not_cover_broad_suffix(self) -> None:
        upstream = {
            update_direct.DomainRule("DOMAIN-SUFFIX", "cn"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "safe.cn"),
        }
        exclusions = {
            update_direct.DomainRule("DOMAIN-SUFFIX", "paypal.com.cn")
        }

        retained, removed = update_direct.filter_domain_rules(upstream, exclusions)

        self.assertEqual(
            retained,
            {
                update_direct.DomainRule("DOMAIN-SUFFIX", "cn"),
                update_direct.DomainRule("DOMAIN-SUFFIX", "safe.cn"),
            },
        )
        self.assertEqual(removed, set())

    def test_index_matches_coverage_semantics(self) -> None:
        exclusions = {
            update_direct.DomainRule("DOMAIN", "exact.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "suffix.example"),
            update_direct.DomainRule("DOMAIN-KEYWORD", "needle"),
            update_direct.DomainRule("DOMAIN-WILDCARD", "api-?.example"),
        }
        candidates = {
            update_direct.DomainRule("DOMAIN", "exact.example"),
            update_direct.DomainRule("DOMAIN", "www.suffix.example"),
            update_direct.DomainRule("DOMAIN", "has-needle.example"),
            update_direct.DomainRule("DOMAIN", "api-1.example"),
            update_direct.DomainRule("DOMAIN", "unrelated.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "www.suffix.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "has-needle.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "unrelated.example"),
            update_direct.DomainRule("DOMAIN-KEYWORD", "a-needle"),
            update_direct.DomainRule("DOMAIN-WILDCARD", "api-?.example"),
        }
        index = update_direct.DomainRuleIndex(exclusions)

        for candidate in candidates:
            with self.subTest(candidate=candidate):
                expected = any(
                    update_direct.domain_rule_covers(exclusion, candidate)
                    for exclusion in exclusions
                )
                self.assertEqual(index.covers(candidate), expected)

    def test_exact_domain_is_removed_when_any_exclusion_type_covers_it(self) -> None:
        upstream = {update_direct.DomainRule("DOMAIN", "api.example.com")}
        exclusions = (
            update_direct.DomainRule("DOMAIN", "api.example.com"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "example.com"),
            update_direct.DomainRule("DOMAIN-KEYWORD", "api.example"),
            update_direct.DomainRule("DOMAIN-WILDCARD", "api.*.com"),
        )

        for exclusion in exclusions:
            with self.subTest(exclusion=exclusion):
                retained, removed = update_direct.filter_domain_rules(
                    upstream, {exclusion}
                )
                self.assertEqual(retained, set())
                self.assertEqual(removed, upstream)

    def test_parent_suffix_and_keyword_cover_narrower_suffix(self) -> None:
        upstream = {
            update_direct.DomainRule("DOMAIN-SUFFIX", "api.example.com"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "needle.test"),
        }
        exclusions = {
            update_direct.DomainRule("DOMAIN-SUFFIX", "example.com"),
            update_direct.DomainRule("DOMAIN-KEYWORD", "needle"),
        }

        retained, removed = update_direct.filter_domain_rules(upstream, exclusions)

        self.assertEqual(retained, set())
        self.assertEqual(removed, upstream)

    def test_hierarchical_filtering_uses_only_ancestor_index(self) -> None:
        upstream = {
            update_direct.DomainRule("DOMAIN", "exact.example"),
            update_direct.DomainRule("DOMAIN", "api.protected.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "protected.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "example"),
        }
        exclusions = {
            update_direct.DomainRule("DOMAIN", "exact.example"),
            update_direct.DomainRule("DOMAIN-SUFFIX", "protected.example"),
        }

        with mock.patch.object(
            update_direct,
            "domain_rule_covers",
            side_effect=AssertionError("pairwise coverage scan used"),
        ):
            retained, removed = update_direct.filter_domain_rules(
                upstream, exclusions
            )

        self.assertEqual(
            retained,
            {update_direct.DomainRule("DOMAIN-SUFFIX", "example")},
        )
        self.assertEqual(
            removed,
            {
                update_direct.DomainRule("DOMAIN", "exact.example"),
                update_direct.DomainRule("DOMAIN", "api.protected.example"),
                update_direct.DomainRule("DOMAIN-SUFFIX", "protected.example"),
            },
        )

    def test_verify_disjoint_uses_coverage_not_overlap(self) -> None:
        broad = update_direct.DomainRule("DOMAIN-SUFFIX", "cn")
        child = update_direct.DomainRule("DOMAIN-SUFFIX", "paypal.com.cn")

        update_direct.verify_disjoint({broad}, [], {child}, [])

        with self.assertRaisesRegex(AssertionError, "still fully covered"):
            update_direct.verify_disjoint({child}, [], {broad}, [])

    def test_output_documents_first_match_ordering(self) -> None:
        output = update_direct.render_output(
            set(),
            [],
            upstream_domain_count=0,
            excluded_domain_count=0,
            redundant_domain_count=0,
            upstream_network_count=0,
            excluded_network_count=0,
            source_digest="0" * 64,
        )

        self.assertIn(
            "# ORDERING: Surge first-match; policy-owned rules MUST precede "
            "this fallback",
            output,
        )
        self.assertIn("partial overlaps are intentional", output)

    def test_redundant_exact_domain_is_minimized(self) -> None:
        rules = {
            update_direct.DomainRule("DOMAIN-SUFFIX", "example.cn"),
            update_direct.DomainRule("DOMAIN", "api.example.cn"),
        }

        self.assertEqual(
            update_direct.minimize_domain_rules(rules),
            {update_direct.DomainRule("DOMAIN-SUFFIX", "example.cn")},
        )


class CidrDifferenceTests(unittest.TestCase):
    def test_single_ip_is_cut_out_without_dropping_parent(self) -> None:
        upstream = [ipaddress.ip_network("192.0.2.0/24")]
        excluded = [ipaddress.ip_network("192.0.2.42/32")]

        retained = update_direct.subtract_networks(upstream, excluded)

        self.assertEqual(sum(network.num_addresses for network in retained), 255)
        self.assertFalse(
            any(
                network.overlaps(excluded_network)
                for network in retained
                for excluded_network in excluded
            )
        )
        self.assertTrue(
            any(ipaddress.ip_address("192.0.2.41") in network for network in retained)
        )
        self.assertFalse(
            any(ipaddress.ip_address("192.0.2.42") in network for network in retained)
        )


if __name__ == "__main__":
    unittest.main()
