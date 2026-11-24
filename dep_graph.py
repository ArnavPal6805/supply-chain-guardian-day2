"""Dependency (discovery) graph: every component, risky or not.

Ported from the Day-1 Guardian's graph analysis and adapted to this codebase's
models: it consumes the `Sbom`, emits a `GraphPayload` whose every edge carries
an `Evidence` object (manifest line, lockfile entry, or an explicit "inferred"
note), and a `DependencyStats` summary.

Per component it computes:
  * depth (1 = direct) and one shortest path from the project,
  * parents / children,
  * `introduced_by`: the direct dependencies whose subtree pulls it in
    (used by root-cause fix recommendations),
  * orphans: a component with no recorded parent is attached to the project as
    an *inferred* direct dependency (so nothing silently disappears from the view).
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set

import networkx as nx

from models import (
    AttackEdge,
    AttackNode,
    DependencyStats,
    Evidence,
    EvidenceKind,
    Finding,
    GraphPayload,
    Sbom,
    Tier,
)

ROOT = "project"


class DependencyIndex:
    """Graph facts about the SBOM, shared by the dependency view and the fix recommender."""

    def __init__(self, sbom: Sbom) -> None:
        self.sbom = sbom
        self.comp = sbom.by_purl()
        g = nx.DiGraph()
        g.add_node(ROOT)
        for c in sbom.components:
            g.add_node(c.purl)
        self.declared: Set[str] = set()
        for c in sbom.components:
            if c.is_direct:
                g.add_edge(ROOT, c.purl)
                self.declared.add(c.purl)
        for src, dsts in sbom.dependencies.items():
            for d in dsts:
                if src in self.comp and d in self.comp and src != d:
                    g.add_edge(src, d)
        # No parent at all: treat as an inferred direct dependency (cdxgen sometimes omits the root edge).
        self.inferred: Set[str] = {c.purl for c in sbom.components
                                   if c.purl not in self.declared and g.in_degree(c.purl) == 0}
        for purl in self.inferred:
            g.add_edge(ROOT, purl)
        self.g = g
        self.direct: Set[str] = self.declared | self.inferred

        # BFS from the project: depth + one shortest path per component (deterministic order).
        pred: Dict[str, Optional[str]] = {ROOT: None}
        depth: Dict[str, int] = {ROOT: 0}
        q = deque([ROOT])
        while q:
            u = q.popleft()
            for v in sorted(g.successors(u), key=lambda n: (n not in self.direct, n)):
                if v not in pred:
                    pred[v] = u
                    depth[v] = depth[u] + 1
                    q.append(v)
        self.depth = depth
        self._pred = pred

        self.introduced_by: Dict[str, Set[str]] = defaultdict(set)
        for d in self.direct:
            for desc in nx.descendants(g, d):
                if desc in self.comp and desc not in self.direct:
                    self.introduced_by[desc].add(d)

    # ---- queries ------------------------------------------------------------ #
    def path(self, purl: str) -> List[str]:
        """Shortest chain of purls from a direct dependency down to `purl` (empty if unreachable)."""
        if purl not in self._pred:
            return []
        out: List[str] = []
        n: Optional[str] = purl
        while n is not None and n != ROOT:
            out.append(n)
            n = self._pred[n]
        return list(reversed(out))

    def parents(self, purl: str) -> List[str]:
        return sorted(p for p in self.g.predecessors(purl) if p in self.comp) if purl in self.g else []

    def children(self, purl: str) -> List[str]:
        return sorted(self.g.successors(purl)) if purl in self.g else []

    def is_direct(self, purl: str) -> bool:
        return purl in self.direct

    def label(self, purl: str) -> str:
        c = self.comp.get(purl)
        return f"{c.name}@{c.version}" if c else purl

    # ---- summary ------------------------------------------------------------ #
    def stats(self) -> DependencyStats:
        comps = self.sbom.components
        depths = Counter(self.depth[c.purl] for c in comps if c.purl in self.depth)
        heaviest = sorted(((len(nx.descendants(self.g, d)), d) for d in self.direct), reverse=True)[:15]
        fan_in = sorted(((len(self.parents(c.purl)), c.purl) for c in comps), reverse=True)[:15]
        versions: Dict[str, Set[str]] = defaultdict(set)
        for c in comps:
            versions[c.name].add(c.version)
        multi = sorted(((n, sorted(vs)) for n, vs in versions.items() if len(vs) > 1), key=lambda x: (-len(x[1]), x[0]))
        return DependencyStats(
            packages=len(comps),
            direct=sum(1 for c in comps if c.purl in self.direct),
            direct_inferred=len(self.inferred),
            transitive=sum(1 for c in comps if c.purl not in self.direct),
            dev_only=sum(1 for c in comps if c.is_dev),
            unreachable=sum(1 for c in comps if c.purl not in self.depth),
            max_depth=max(depths) if depths else 0,
            depth_histogram=dict(sorted(depths.items())),
            edges=sum(1 for a, b in self.g.edges if a in self.comp and b in self.comp),
            without_integrity=sum(1 for c in comps if not c.hashes),
            heaviest_direct=[{"id": d, "label": self.label(d), "pulls_in": n} for n, d in heaviest if n],
            most_depended_on=[{"id": p, "label": self.label(p), "parents": n} for n, p in fan_in if n > 1],
            multiple_versions=[{"name": n, "versions": vs} for n, vs in multi[:30]],
        )


def build_dependency_graph(sbom: Sbom, findings: Iterable[Finding], project_name: str,
                           index: Optional[DependencyIndex] = None) -> GraphPayload:
    """Project -> direct deps -> transitive deps, with each package's worst finding overlaid."""
    idx = index or DependencyIndex(sbom)
    worst: Dict[str, Finding] = {}
    ids: Dict[str, List[str]] = {}
    for f in findings:
        if not f.purl:
            continue
        ids.setdefault(f.purl, []).append(f.id)
        if f.purl not in worst or f.elo.total > worst[f.purl].elo.total:
            worst[f.purl] = f
    comp = idx.comp
    manifest_occ = {c.purl: next((o for o in c.occurrences if o.file_path == "package.json"), None)
                    for c in sbom.components}
    root_specs = sbom.edge_specs.get(ROOT, {})

    edges: List[AttackEdge] = []
    for a, b in idx.g.edges:
        if a == ROOT:
            c = comp[b]
            if b in idx.inferred:
                ev = Evidence(kind=EvidenceKind.LOCKFILE, file=sbom.lockfile or "sbom.json",
                              detail=f"{c.name}@{c.version} has no recorded parent; attached to the project (inferred direct)")
                rel = "inferred"
            else:
                occ = manifest_occ.get(b)
                ev = Evidence(kind=EvidenceKind.MANIFEST, file="package.json", line=occ.line_number if occ else None,
                              detail=occ.text if occ else f'"{c.name}": "{root_specs.get(b, c.version)}"')
                rel = "declares"
        else:
            spec = sbom.edge_specs.get(a, {}).get(b)
            ev = Evidence(kind=EvidenceKind.LOCKFILE, file=sbom.lockfile or "sbom.json",
                          detail=f"{comp[a].name}@{comp[a].version} -> {comp[b].name}@{comp[b].version}"
                                 + (f" (requires {spec})" if spec else ""))
            rel = "depends_on"
        edges.append(AttackEdge(source=a, target=b, relation=rel, evidence=ev))

    nodes = [AttackNode(id=ROOT, label=f"{project_name}\n(project)", tier=Tier.EXPOSURE, depth=0,
                        attrs={"root": True, "components": len(sbom.components)})]
    for c in sbom.components:
        f = worst.get(c.purl)
        intro = sorted(idx.introduced_by.get(c.purl, set()))
        nodes.append(AttackNode(
            id=c.purl, label=f"{c.name}@{c.version}",
            tier=Tier.DIRECT_PKG if c.purl in idx.direct else Tier.TRANSITIVE_PKG,
            depth=idx.depth.get(c.purl, 0), purl=c.purl, risk_elo=f.elo.total if f else None,
            severity=f.elo.severity if f else None, finding_ids=sorted(ids.get(c.purl, [])),
            attrs={"dev": c.is_dev, "version_source": c.version_source,
                   "direct_inferred": c.purl in idx.inferred,
                   "declared_spec": root_specs.get(c.purl),
                   "dependencies": idx.g.out_degree(c.purl), "dependents": len(idx.parents(c.purl)),
                   "reachable_from_project": c.purl in idx.depth,
                   "path": idx.path(c.purl),
                   "introduced_by": intro[:8], "introduced_by_count": len(intro),
                   "occurrences": [f"{o.file_path}:{o.line_number}" for o in c.occurrences[:4]]}))
    return GraphPayload(nodes=nodes, edges=edges)
