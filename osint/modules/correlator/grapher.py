"""Merge saved scan results into one entity graph and render it as HTML.

Nodes are keyed by entity type and value (``domain:example.com``), so the same
entity found by different scans becomes one node, and that shared node is the
correlation.
"""

import html
import json
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

import networkx as nx
from pyvis.network import Network

from osint.core.exceptions import ValidationError
from osint.core.logger import logger

CASE_RESULTS_DIR = "results"
MAX_SUBDOMAIN_NODES = 50
TARGET_NODE_SIZE = 28
DEFAULT_NODE_SIZE = 14
DEFAULT_COLOR = "#95a5a6"
PLACEHOLDER_VALUES = frozenset({"Not Available", "Not Available / Ported"})
NODE_COLORS = {
    "username": "#e74c3c",
    "email": "#9b59b6",
    "phone": "#e67e22",
    "domain": "#34495e",
    "ip": "#1abc9c",
    "url": "#f39c12",
    "host": "#7f8c8d",
    "org": "#2ecc71",
    "asn": "#16a085",
    "carrier": "#3498db",
    "country": "#f1c40f",
    "location": "#c0392b",
    "file": "#8e44ad",
    "device": "#d35400",
    "name": "#27ae60",
    "avatar": "#e84393",
}
AVATAR_NODE_ID_CHARS = 16

Builder = Callable[[nx.Graph, str, dict[str, Any]], None]


def _module_of(entry: dict[str, Any]) -> Any:
    # "module" is accepted for result files written before 0.2.0.
    return entry.get("module_name") or entry.get("module")


def _is_result(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("target"), str)
        and isinstance(_module_of(entry), str)
        and isinstance(entry.get("data", {}), dict)
    )


def _read_results(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ValidationError(f"File not found: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Cannot parse {path}: {exc}") from exc
    entries = document if isinstance(document, list) else [document]
    if not entries or not all(_is_result(entry) for entry in entries):
        raise ValidationError(
            f"{path} is not OSINT Toolkit result output (use --json to create one)."
        )
    return entries


def _result_files(path: Path) -> list[Path]:
    """A file as-is; a case folder (or any folder) as the JSON results inside it."""
    if not path.is_dir():
        return [path]
    case_results = path / CASE_RESULTS_DIR
    folder = case_results if case_results.is_dir() else path
    # Symlinks could pull in files from outside the case; only read real files.
    files = sorted(p for p in folder.glob("*.json") if not p.is_symlink())
    if not files:
        raise ValidationError(f"No result files found in {path}")
    return files


def load_results(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    return [
        entry
        for path in paths
        for file in _result_files(Path(path))
        for entry in _read_results(file)
    ]


def _add_node(
    graph: nx.Graph,
    kind: str,
    value: Any,
    *,
    label: str | None = None,
    title: str | None = None,
    is_target: bool = False,
) -> str:
    node = f"{kind}:{value}"
    if node not in graph or is_target:
        graph.add_node(
            node,
            label=label or str(value),
            # pyvis shows titles via innerHTML, and values come from remote data
            # (PTR records, EXIF, WHOIS), so escape them.
            title=html.escape(title or f"{kind}: {value}"),
            color=NODE_COLORS.get(kind, DEFAULT_COLOR),
            size=TARGET_NODE_SIZE if is_target else DEFAULT_NODE_SIZE,
            group=kind,
        )
    return node


def _link(
    graph: nx.Graph,
    source: str,
    kind: str,
    value: Any,
    relation: str,
    *,
    dashed: bool = False,
    **node_attrs: Any,
) -> str | None:
    if value in (None, "") or value in PLACEHOLDER_VALUES:
        return None
    node = _add_node(graph, kind, value, **node_attrs)
    graph.add_edge(source, node, label=relation, title=relation, dashes=dashed)
    return node


def _username(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    root = _add_node(graph, "username", data.get("username") or target, is_target=True)
    for account in data.get("accounts", []):
        site = account.get("site") or account.get("url")
        account_node = _link(
            graph,
            root,
            "url",
            account.get("url"),
            "has_account",
            label=site,
            title=f"{site} ({account.get('tier', 'unverified')})",
        )
        if account_node:
            _link_profile(graph, account_node, account.get("profile") or {})
    attribution = data.get("attribution") or {}
    for match in attribution.get("avatar_matches", []):
        _link_avatar_match(graph, match)


def _link_profile(graph: nx.Graph, account_node: str, profile: dict[str, Any]) -> None:
    # Shared names and links become shared nodes, which is how accounts connect.
    _link(graph, account_node, "name", profile.get("name"), "display_name")
    for link in profile.get("links") or []:
        _link(graph, account_node, "url", link, "links_to")


def _link_avatar_match(graph: nx.Graph, match: dict[str, Any]) -> None:
    node = _add_node(
        graph,
        "avatar",
        match["fingerprint"][:AVATAR_NODE_ID_CHARS],
        label="Same avatar",
        title=f"{match['method']}: {', '.join(match['sites'])}",
    )
    for url in match.get("urls", []):
        account_node = f"url:{url}"
        if account_node in graph:
            graph.add_edge(account_node, node, label="same_avatar", title="same_avatar")


def _email(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    root = _add_node(graph, "email", data.get("normalized") or target, is_target=True)
    domain = _link(graph, root, "domain", data.get("domain"), "uses_domain")
    for host in data.get("mx_records", []):
        if domain:
            _link(graph, domain, "host", host, "mail_handled_by")
    candidate = (data.get("pivots") or {}).get("username_candidate")
    _link(graph, root, "username", candidate, "possible_username", dashed=True)


def _ip(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    root = _add_node(graph, "ip", data.get("ip") or target, is_target=True)
    reverse = data.get("reverse_dns")
    for host in reverse if isinstance(reverse, list) else []:
        _link(graph, root, "domain", host, "reverse_dns")
    whois = (data.get("whois") or {}).get("data") or {}
    asn = whois.get("asn")
    label = f"AS{asn} {whois.get('asn_description') or ''}".strip() if asn else None
    _link(graph, root, "asn", asn, "announced_by", label=label)


def _domain(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    if data.get("target_type") == "ip":
        _ip(graph, target, data)
        return
    root = _add_node(graph, "domain", data.get("domain") or target, is_target=True)
    dns = data.get("dns") or {}
    for address in [*dns.get("A", []), *dns.get("AAAA", [])]:
        _link(graph, root, "ip", address, "resolves_to")
    for host in dns.get("MX", []):
        _link(graph, root, "host", host, "mail_handled_by")
    for host in dns.get("NS", []):
        _link(graph, root, "host", host, "name_server")
    subdomains = (data.get("ct_logs") or {}).get("subdomains", [])
    for subdomain in subdomains[:MAX_SUBDOMAIN_NODES]:
        _link(graph, root, "domain", subdomain, "has_subdomain")
    whois = (data.get("whois") or {}).get("data") or {}
    _link(graph, root, "org", whois.get("registrant_organization"), "registered_to")


def _phone(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    core = data.get("core") or {}
    root = _add_node(graph, "phone", core.get("e164") or target, is_target=True)
    _link(graph, root, "carrier", core.get("carrier"), "allocated_to")
    _link(graph, root, "country", core.get("region_code"), "registered_in")


def _metadata(graph: nx.Graph, target: str, data: dict[str, Any]) -> None:
    root = _add_node(graph, "file", target, label=Path(target).name, is_target=True)
    gps = data.get("gps")
    if gps:
        coordinates = f"{gps['latitude']},{gps['longitude']}"
        _link(
            graph,
            root,
            "location",
            coordinates,
            "taken_at",
            title=gps.get("google_maps"),
        )
    exif = data.get("exif") or {}
    device = " ".join(
        filter(None, (exif.get("Image Make"), exif.get("Image Model")))
    ).strip()
    _link(graph, root, "device", device, "captured_with")
    _link(graph, root, "device", exif.get("EXIF BodySerialNumber"), "camera_serial")


BUILDERS: dict[str, Builder] = {
    "username": _username,
    "email": _email,
    "domain": _domain,
    "phone": _phone,
    "metadata": _metadata,
}


def build_graph(results: Iterable[dict[str, Any]]) -> nx.Graph:
    graph = nx.Graph()
    for entry in results:
        builder = BUILDERS.get(_module_of(entry))
        if builder is None:
            logger.debug("No graph builder for module %r", _module_of(entry))
            continue
        builder(graph, entry["target"], entry.get("data") or {})
    return graph


def render_graph(graph: nx.Graph, output_path: Path) -> Path:
    network = Network(
        height="800px",
        width="100%",
        bgcolor="#1e1e1e",
        font_color="white",
        select_menu=True,
        filter_menu=True,
        cdn_resources="in_line",
    )
    network.barnes_hut(
        gravity=-8000,
        central_gravity=0.3,
        spring_length=200,
        spring_strength=0.04,
        damping=0.09,
    )
    network.from_nx(graph)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    network.write_html(str(output_path))
    logger.info("Graph written to %s", output_path)
    return output_path


def build_graph_from_json(paths: Sequence[str | Path], output_path: str | Path) -> Path:
    """Merge one or more result files into a single interactive HTML graph."""
    graph = build_graph(load_results(paths))
    if graph.number_of_nodes() == 0:
        raise ValidationError("No graphable results found in the given files.")
    return render_graph(graph, Path(output_path))
