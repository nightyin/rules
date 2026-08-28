#!/usr/bin/env python3
"""Build a policy-safe Surge DIRECT fallback from maintained rule sets.

When ordered after the policy-owned rules, the effective policy is:

    (SKK domestic/direct domains + Loyalsoldier direct domains + SKK China IPv4)
      - policy-owned rules in direct-exclusions.conf

Surge uses first-match ordering. Policy-owned rules MUST appear before this
fallback DIRECT rule set, so partial domain overlaps are intentional and safe:
an upstream domain rule is removed only when an exclusion fully covers every
hostname it can match. CIDR exclusions are exact: an excluded /32 punches a
/32 hole instead of dropping the entire containing China network.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import ipaddress
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "direct.list"
EXCLUSIONS_PATH = ROOT / "direct-exclusions.conf"
USER_AGENT = "nightyin-direct-builder/1.0 (+https://github.com/nightyin/rules)"
FETCH_TIMEOUT = 30
FETCH_LIMIT = 10_000_000
FETCH_ATTEMPTS = 3

DOMAIN_TYPES = (
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
)
IP_TYPES = ("IP-CIDR", "IP-CIDR6")
SUPPORTED_TYPES = set(DOMAIN_TYPES + IP_TYPES)


@dataclass(frozen=True, order=True)
class DomainRule:
    rule_type: str
    value: str


@dataclass(frozen=True)
class Source:
    name: str
    location: str
    plain_domain_set: bool = False


UPSTREAM_SOURCES = (
    Source(
        "skk-domestic",
        "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List/non_ip/domestic.conf",
    ),
    Source(
        "skk-direct",
        "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List/non_ip/direct.conf",
    ),
    Source(
        "loyalsoldier-direct-domain-set",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt",
        plain_domain_set=True,
    ),
    Source(
        "skk-china-ip",
        "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List/ip/china_ip.conf",
    ),
)


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def suffix_covers(suffix: str, domain: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def fetch_text(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                body = response.read(FETCH_LIMIT + 1)
                if len(body) > FETCH_LIMIT:
                    raise ValueError(f"source exceeds {FETCH_LIMIT} bytes: {url}")
                charset = response.headers.get_content_charset() or "utf-8"
                return body.decode(charset, errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt < FETCH_ATTEMPTS:
                time.sleep(0.5 * attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_error}") from last_error


def read_local_source(location: str) -> str:
    relative = location.removeprefix("local:")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"local source escapes repository: {location}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"missing local exclusion source: {path}")
    return path.read_text(encoding="utf-8")


def load_source(source: Source) -> tuple[Source, str]:
    if source.location.startswith("local:"):
        return source, read_local_source(source.location)
    return source, fetch_text(source.location)


def parse_rules(
    text: str,
    *,
    source_name: str,
    plain_domain_set: bool = False,
) -> tuple[set[DomainRule], list[ipaddress._BaseNetwork]]:
    domains: set[DomainRule] = set()
    networks: list[ipaddress._BaseNetwork] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";", "[")):
            continue

        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()
        if len(parts) >= 2 and rule_type in DOMAIN_TYPES:
            value = normalize_domain(parts[1])
            if not value:
                raise ValueError(
                    f"empty domain rule in {source_name}:{line_number}"
                )
            domains.add(DomainRule(rule_type, value))
            continue

        if len(parts) >= 2 and rule_type in IP_TYPES:
            try:
                network = ipaddress.ip_network(parts[1], strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"invalid CIDR in {source_name}:{line_number}: {parts[1]}"
                ) from exc
            expected_version = 4 if rule_type == "IP-CIDR" else 6
            if network.version != expected_version:
                raise ValueError(
                    f"CIDR family mismatch in {source_name}:{line_number}: {parts[1]}"
                )
            networks.append(network)
            continue

        if plain_domain_set and len(parts) == 1 and " " not in line:
            is_suffix = line.startswith((".", "*."))
            value = normalize_domain(line.lstrip("."))
            if value:
                rule_type = "DOMAIN-SUFFIX" if is_suffix else "DOMAIN"
                domains.add(DomainRule(rule_type, value))

    return domains, networks


def parse_exclusion_manifest() -> tuple[list[Source], str]:
    text = EXCLUSIONS_PATH.read_text(encoding="utf-8")
    sources: list[Source] = []
    inline_lines: list[str] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()
        if rule_type == "RULE-SET":
            if len(parts) != 2 or not parts[1]:
                raise ValueError(
                    f"invalid RULE-SET in {EXCLUSIONS_PATH.name}:{line_number}"
                )
            location = parts[1]
            sources.append(Source(location, location))
        elif rule_type in SUPPORTED_TYPES:
            inline_lines.append(line)
        else:
            raise ValueError(
                f"unsupported exclusion in {EXCLUSIONS_PATH.name}:{line_number}: {line}"
            )

    if not sources:
        raise ValueError("exclusion manifest has no RULE-SET sources")
    return sources, "\n".join(inline_lines)


def domain_rule_matches_anchor(rule: DomainRule, anchor: str) -> bool:
    if rule.rule_type == "DOMAIN":
        return anchor == rule.value
    if rule.rule_type == "DOMAIN-SUFFIX":
        return suffix_covers(rule.value, anchor)
    if rule.rule_type == "DOMAIN-KEYWORD":
        return rule.value in anchor
    if rule.rule_type == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(anchor, rule.value)
    raise ValueError(f"unsupported domain rule: {rule}")


def domain_rule_covers(covering: DomainRule, covered: DomainRule) -> bool:
    """Return whether one rule covers every hostname matched by another.

    Wildcard language containment is not generally decidable with fnmatch's
    syntax, so non-identical wildcard rule sets are retained conservatively.
    """

    if covered.rule_type == "DOMAIN":
        return domain_rule_matches_anchor(covering, covered.value)
    if covering == covered:
        return True
    if covered.rule_type == "DOMAIN-SUFFIX":
        if covering.rule_type == "DOMAIN-SUFFIX":
            return suffix_covers(covering.value, covered.value)
        if covering.rule_type == "DOMAIN-KEYWORD":
            return covering.value in covered.value
        return False
    if covered.rule_type == "DOMAIN-KEYWORD":
        return (
            covering.rule_type == "DOMAIN-KEYWORD"
            and covering.value in covered.value
        )
    if covered.rule_type == "DOMAIN-WILDCARD":
        return False
    raise ValueError(f"unsupported domain rule: {covered}")


_DOMAIN_BIT = 1
_SUFFIX_BIT = 2
_RULE_TYPE_BITS = {
    "DOMAIN": _DOMAIN_BIT,
    "DOMAIN-SUFFIX": _SUFFIX_BIT,
}


class _DomainTrieNode:
    __slots__ = ("children", "terminal_mask")

    def __init__(self) -> None:
        self.children: dict[str, _DomainTrieNode] = {}
        self.terminal_mask = 0


def _domain_labels(value: str) -> tuple[str, ...]:
    return tuple(reversed(value.split(".")))


def _insert_domain_value(root: _DomainTrieNode, value: str, rule_type: str) -> None:
    bit = _RULE_TYPE_BITS[rule_type]
    node = root
    for label in _domain_labels(value):
        node = node.children.setdefault(label, _DomainTrieNode())
    node.terminal_mask |= bit


def _has_covering_suffix(
    root: _DomainTrieNode,
    value: str,
    *,
    include_equal: bool = True,
) -> bool:
    labels = _domain_labels(value)
    node = root
    for index, label in enumerate(labels):
        node = node.children.get(label)
        if node is None:
            return False
        if node.terminal_mask & _SUFFIX_BIT and (
            include_equal or index < len(labels) - 1
        ):
            return True
    return False


class DomainRuleIndex:
    """Index exact/suffix exclusions for near-linear ancestor queries."""

    def __init__(self, rules: Iterable[DomainRule]) -> None:
        self.rules = tuple(rules)
        self._root = _DomainTrieNode()
        for rule in self.rules:
            if rule.rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
                _insert_domain_value(self._root, rule.value, rule.rule_type)
        self._non_hierarchical = tuple(
            rule
            for rule in self.rules
            if rule.rule_type not in ("DOMAIN", "DOMAIN-SUFFIX")
        )

    def covers(self, rule: DomainRule) -> bool:
        if rule.rule_type not in ("DOMAIN", "DOMAIN-SUFFIX"):
            return any(
                domain_rule_covers(excluded, rule) for excluded in self.rules
            )

        node = self._root
        for label in _domain_labels(rule.value):
            node = node.children.get(label)
            if node is None:
                break
            if node.terminal_mask & _SUFFIX_BIT:
                return True
        else:
            if rule.rule_type == "DOMAIN":
                if node.terminal_mask & _DOMAIN_BIT:
                    return True

        return any(
            domain_rule_covers(excluded, rule)
            for excluded in self._non_hierarchical
        )


def filter_domain_rules(
    upstream: set[DomainRule],
    exclusions: set[DomainRule],
    exclusion_index: DomainRuleIndex | None = None,
) -> tuple[set[DomainRule], set[DomainRule]]:
    retained: set[DomainRule] = set()
    removed: set[DomainRule] = set()
    index = exclusion_index or DomainRuleIndex(exclusions)

    for rule in upstream:
        if index.covers(rule):
            removed.add(rule)
        else:
            retained.add(rule)
    return retained, removed


def minimize_domain_rules(rules: set[DomainRule]) -> set[DomainRule]:
    suffixes = {
        rule.value for rule in rules if rule.rule_type == "DOMAIN-SUFFIX"
    }
    all_suffixes = _DomainTrieNode()
    for suffix in suffixes:
        _insert_domain_value(all_suffixes, suffix, "DOMAIN-SUFFIX")
    kept_suffixes = {
        suffix
        for suffix in suffixes
        if not _has_covering_suffix(all_suffixes, suffix, include_equal=False)
    }

    kept_suffix_index = _DomainTrieNode()
    for suffix in kept_suffixes:
        _insert_domain_value(kept_suffix_index, suffix, "DOMAIN-SUFFIX")

    minimized = {
        rule
        for rule in rules
        if rule.rule_type not in ("DOMAIN", "DOMAIN-SUFFIX")
    }
    minimized.update(DomainRule("DOMAIN-SUFFIX", value) for value in kept_suffixes)
    for rule in rules:
        if rule.rule_type != "DOMAIN":
            continue
        if not _has_covering_suffix(kept_suffix_index, rule.value):
            minimized.add(rule)
    return minimized


def collapse_networks(
    networks: Iterable[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for version in (4, 6):
        same_version = [network for network in networks if network.version == version]
        result.extend(ipaddress.collapse_addresses(same_version))
    return result


def subtract_network(
    network: ipaddress._BaseNetwork,
    exclusions: Sequence[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    remaining = [network]
    for excluded in exclusions:
        if excluded.version != network.version:
            continue
        next_remaining: list[ipaddress._BaseNetwork] = []
        for candidate in remaining:
            if not candidate.overlaps(excluded):
                next_remaining.append(candidate)
            elif excluded == candidate or excluded.supernet_of(candidate):
                continue
            elif candidate.supernet_of(excluded):
                next_remaining.extend(candidate.address_exclude(excluded))
            else:
                raise AssertionError(
                    f"unexpected non-contained CIDR overlap: {candidate} / {excluded}"
                )
        remaining = next_remaining
        if not remaining:
            break
    return remaining


def subtract_networks(
    upstream: Sequence[ipaddress._BaseNetwork],
    exclusions: Sequence[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    collapsed_exclusions = collapse_networks(exclusions)
    retained: list[ipaddress._BaseNetwork] = []
    for network in collapse_networks(upstream):
        relevant = [
            excluded
            for excluded in collapsed_exclusions
            if excluded.version == network.version and network.overlaps(excluded)
        ]
        retained.extend(subtract_network(network, relevant))
    return collapse_networks(retained)


def verify_disjoint(
    domains: set[DomainRule],
    networks: Sequence[ipaddress._BaseNetwork],
    excluded_domains: set[DomainRule],
    excluded_networks: Sequence[ipaddress._BaseNetwork],
    exclusion_index: DomainRuleIndex | None = None,
) -> None:
    """Reject redundant covered domains and any remaining CIDR intersections."""

    index = exclusion_index or DomainRuleIndex(excluded_domains)
    domain_conflicts: list[tuple[DomainRule, DomainRule]] = []
    for domain in domains:
        if not index.covers(domain):
            continue
        excluded = next(
            excluded
            for excluded in excluded_domains
            if domain_rule_covers(excluded, domain)
        )
        domain_conflicts.append((domain, excluded))
        if len(domain_conflicts) == 5:
            break
    if domain_conflicts:
        sample = ", ".join(
            f"{left.rule_type},{left.value} <> {right.rule_type},{right.value}"
            for left, right in domain_conflicts
        )
        raise AssertionError(f"generated domain rules still fully covered: {sample}")

    ip_conflicts = [
        (network, excluded)
        for network in networks
        for excluded in excluded_networks
        if network.version == excluded.version and network.overlaps(excluded)
    ]
    if ip_conflicts:
        sample = ", ".join(
            f"{left} <> {right}" for left, right in ip_conflicts[:5]
        )
        raise AssertionError(f"generated IP rules still intersect: {sample}")


def domain_sort_key(rule: DomainRule) -> tuple[int, str]:
    return (DOMAIN_TYPES.index(rule.rule_type), rule.value)


def network_sort_key(network: ipaddress._BaseNetwork) -> tuple[int, int, int]:
    return (network.version, int(network.network_address), network.prefixlen)


def render_output(
    domains: set[DomainRule],
    networks: Sequence[ipaddress._BaseNetwork],
    *,
    upstream_domain_count: int,
    excluded_domain_count: int,
    redundant_domain_count: int,
    upstream_network_count: int,
    excluded_network_count: int,
    source_digest: str,
) -> str:
    ipv4_count = sum(network.version == 4 for network in networks)
    ipv6_count = sum(network.version == 6 for network in networks)
    lines = [
        "# NAME: Direct-Filtered",
        "# AUTHOR: nightyin",
        "# GENERATED-BY: scripts/update_direct.py",
        "# UPSTREAM: SukkaLab/ruleset.skk.moe + Loyalsoldier/surge-rules",
        "# EXCLUSIONS: direct-exclusions.conf",
        f"# SOURCE-SHA256: {source_digest}",
        f"# UPSTREAM-DOMAIN-RULES: {upstream_domain_count}",
        f"# EXCLUDED-DOMAIN-RULES: {excluded_domain_count}",
        f"# REDUNDANT-DOMAIN-RULES: {redundant_domain_count}",
        f"# RETAINED-DOMAIN-RULES: {len(domains)}",
        f"# UPSTREAM-IP-RULES: {upstream_network_count}",
        f"# EXCLUSION-IP-RULES: {excluded_network_count}",
        f"# RETAINED-IPV4-RULES: {ipv4_count}",
        f"# RETAINED-IPV6-RULES: {ipv6_count}",
        "# ORDERING: Surge first-match; policy-owned rules MUST precede this fallback",
        "# POLICY: remove only fully covered domains; partial overlaps are intentional",
        "",
    ]
    lines.extend(
        f"{rule.rule_type},{rule.value}" for rule in sorted(domains, key=domain_sort_key)
    )
    if domains and networks:
        lines.append("")
    for network in sorted(networks, key=network_sort_key):
        rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        lines.append(f"{rule_type},{network},no-resolve")
    return "\n".join(lines).rstrip() + "\n"


def build() -> str:
    exclusion_sources, inline_exclusions = parse_exclusion_manifest()
    all_sources = list(UPSTREAM_SOURCES) + exclusion_sources
    loaded: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(load_source, source) for source in all_sources]
        for future in concurrent.futures.as_completed(futures):
            source, text = future.result()
            loaded[source.name] = text

    upstream_domains: set[DomainRule] = set()
    upstream_networks: list[ipaddress._BaseNetwork] = []
    for source in UPSTREAM_SOURCES:
        domains, networks = parse_rules(
            loaded[source.name],
            source_name=source.name,
            plain_domain_set=source.plain_domain_set,
        )
        upstream_domains.update(domains)
        upstream_networks.extend(networks)

    if len(upstream_domains) < 50_000:
        raise RuntimeError(
            f"domain upstreams unexpectedly small: {len(upstream_domains)}"
        )
    if len(upstream_networks) < 3500:
        raise RuntimeError(
            f"SKK IP upstream unexpectedly small: {len(upstream_networks)}"
        )

    excluded_domains, excluded_networks = parse_rules(
        inline_exclusions,
        source_name=EXCLUSIONS_PATH.name,
    )
    for source in exclusion_sources:
        domains, networks = parse_rules(
            loaded[source.name],
            source_name=source.name,
            plain_domain_set=source.plain_domain_set,
        )
        if not domains and not networks:
            raise RuntimeError(f"exclusion source has no supported rules: {source.name}")
        excluded_domains.update(domains)
        excluded_networks.extend(networks)

    exclusion_index = DomainRuleIndex(excluded_domains)
    filtered_domains, removed_domains = filter_domain_rules(
        upstream_domains,
        excluded_domains,
        exclusion_index,
    )
    pre_minimize_count = len(filtered_domains)
    filtered_domains = minimize_domain_rules(filtered_domains)
    redundant_domain_count = pre_minimize_count - len(filtered_domains)
    filtered_networks = subtract_networks(upstream_networks, excluded_networks)
    verify_disjoint(
        filtered_domains,
        filtered_networks,
        excluded_domains,
        excluded_networks,
        exclusion_index,
    )

    digest = hashlib.sha256()
    for source in sorted(all_sources, key=lambda item: item.name):
        digest.update(source.name.encode())
        digest.update(b"\0")
        digest.update(loaded[source.name].encode())
        digest.update(b"\0")
    digest.update(EXCLUSIONS_PATH.read_bytes())

    print(
        "Direct-Filtered: "
        f"domains {len(upstream_domains)} -> {len(filtered_domains)} "
        f"(excluded={len(removed_domains)}, redundant={redundant_domain_count}), "
        f"IP rules {len(upstream_networks)} -> {len(filtered_networks)}, "
        f"protected domains={len(excluded_domains)}, "
        f"protected IP rules={len(excluded_networks)}"
    )
    if removed_domains:
        print(
            "Removed domain rules: "
            + ", ".join(
                f"{rule.rule_type},{rule.value}"
                for rule in sorted(removed_domains, key=domain_sort_key)
            )
        )

    return render_output(
        filtered_domains,
        filtered_networks,
        upstream_domain_count=len(upstream_domains),
        excluded_domain_count=len(removed_domains),
        redundant_domain_count=redundant_domain_count,
        upstream_network_count=len(upstream_networks),
        excluded_network_count=len(excluded_networks),
        source_digest=digest.hexdigest(),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify direct.list is current without modifying it",
    )
    args = parser.parse_args()

    try:
        output = build()
    except (OSError, RuntimeError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if not OUTPUT_PATH.exists():
            print(f"error: missing {OUTPUT_PATH.name}", file=sys.stderr)
            return 1
        if OUTPUT_PATH.read_text(encoding="utf-8") != output:
            print(f"error: {OUTPUT_PATH.name} is out of date", file=sys.stderr)
            return 1
        print(
            f"{OUTPUT_PATH.name} is current and has no fully covered protected rules"
        )
        return 0

    OUTPUT_PATH.write_text(output, encoding="utf-8")
    print(f"wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
