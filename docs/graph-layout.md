# Dynamic graph layout

The playground draws the actual links reported by its local transport simulator.
Placement is a UI concern: it does not influence discovery, routing, storage or
cryptographic evaluation. Camera pan and zoom transform the same world coordinates
for nodes, links, traffic and the background grid.

## Options considered

| Approach | Fit for this graph | Tradeoff |
| --- | --- | --- |
| [Fruchterman–Reingold force-directed placement](https://reingold.co/force-directed.pdf) | Undirected peer links; smooth incremental spring movement; simple bounded steps in native Rust | Forces alone neither prevent rectangle overlap nor guarantee minimal crossings |
| [Stress majorization, as used by Graphviz neato](https://graphviz.org/docs/layouts/neato/) | Good general undirected layouts and a useful alternative for larger graphs | Requires graph distances and a global optimization pass; maintaining existing positions needs additional constraints |
| [Constraint layout, as used by WebCola](https://ialab.it.monash.edu/webcola/doc/classes/_layout_.layout.html) | Explicit width/height and separation constraints solve the card-overlap problem | A full constraint solver is more machinery than this small prototype needs |
| [ELK layered/Sugiyama layout](https://eclipse.dev/elk/reference/algorithms/org-eclipse-elk-layered.html) | Useful for directed hierarchies and left-to-right flows | An undirected cyclic peer mesh has no intrinsic hierarchy; artificial layers would imply a network structure that is absent |

Crossing minimization is a separate objective from preventing overlapping nodes.
[ELK exposes several crossing heuristics](https://eclipse.dev/elk/reference/groups/org-eclipse-elk-layered-crossingMinimization.html),
and even ordering a two-layer graph to minimize straight-edge crossings is
[NP-hard](https://jgaa.info/index.php/jgaa/article/download/paper1/2965/2771).
The [graph-drawing handbook](https://cs.brown.edu/people/rtamassi/gdhandbook/chapters/force-directed.pdf)
also explains why a force-directed algorithm does not guarantee a crossing-free
drawing even for planar input. Some peer graphs are nonplanar, so a universal
zero-crossing promise would be incorrect.

## Sparse placement

[`graph_layout.rs`](../crates/fhe-playground/src/graph_layout.rs) is a small,
dependency-free incremental spring layout inspired by the force-directed family.
It is not a port or a full implementation of WebCola, ELK or Graphviz.

- Stable IDs retain their world positions when nodes or links change. New nodes
  start at their requested world position, or near existing connected neighbors.
- Supplied edges alone create attractive forces. Pairwise repulsion creates room
  around node cards. A weak anchor toward each node's previous position preserves
  the user's mental map rather than recentering on every join.
- Rectangular separation projects overlapping cards apart, with a deterministic
  packing fallback for coincident or unusually dense input. Card dimensions and
  a 24-unit margin are respected after every solver call.
- A bounded local search swaps same-role endpoints of crossed links when this
  reduces straight-edge crossings without introducing card overlap. It is a
  heuristic; an improvement can reposition the two cards rather than animate a
  collision-free trajectory between their previous locations.
- Sorting by ID, a fixed seed calculation and fixed iteration budgets make a
  layout reproducible independently of input ordering. Changed topology reheats
  240 solver iterations; unchanged settled input does not continue drifting.

The placement solver is intended for small graphs (about 48 nodes); the local
network currently permits 16 peers and 8 clients. Force and separation passes are
quadratic in node count. Crossing refinement runs periodically and tests at most
24 endpoint swaps. It improves simple crossed-cycle fixtures; it does not certify
global optimality, edge-disjoint routes or a planar embedding. Graphviz documents
[PRISM/VPSC overlap removal](https://graphviz.org/docs/attrs/overlap/) and the
[difference between node and node/edge overlap](https://graphviz.org/faq/#how-can-i-avoid-node-edge-overlaps-in-neato).

## Dense topology without hiding links

An all-to-all peer mesh has quadratically many links. Improving node placement
alone cannot make every edge easy to follow. The original
[Ghoniem, Fekete and Castagliola readability study](https://courses.ischool.berkeley.edu/i247/f05/readings/Ghoniem-GraphReadability_InfoVis04.pdf)
compared node-link and adjacency-matrix diagrams on several tasks and graph
densities. Matrix diagrams performed better on most tasks above twenty vertices;
path finding consistently favored node-link diagrams. These results support an
exact matrix view for dense link/neighbor inspection and a map for spatial
interaction and packet tracing. They do not validate this playground's specific
threshold or establish that a matrix is best for every task.

[Holten's hierarchical edge bundling](https://research.tue.nl/en/publications/hierarchical-edge-bundles-visualization-of-adjacency-relations-in/)
uses an existing containment hierarchy to guide curves. The peer network has no
such hierarchy, so fabricating a relay tree would misrepresent topology.
[Force-directed edge bundling](https://onlinelibrary.wiley.com/doi/abs/10.1111/j.1467-8659.2009.01450.x)
groups compatible curves without a hierarchy, while
[ordered bundles](https://arxiv.org/abs/1209.4227) retain distinguishable individual
edge lanes. These are useful alternatives for richer future exploration. The
prototype implements a simpler bounded shared-lane scheme, not either paper's
complete algorithm.

The implemented dense condition is at least eight nodes and at least twice as
many distinct actual undirected links as nodes. It changes presentation only:

- Existing node IDs retain their immediate positions on `sync`, and new nodes
  honor their initial seeds. Solver steps then move them to a deterministic outer
  ring, retaining their angular order. Its radius accounts for the largest padded
  card diagonal, so the settled ring has room for every rectangle. Every intermediate
  solver call also resolves rectangle overlaps.
- [`graph_bundling.rs`](../crates/fhe-playground/src/graph_bundling.rs) retains every
  supplied actual edge ID pair. Each path attaches to a shared rectangle outside
  all node cards, follows its shorter perimeter direction, and returns to its
  destination. The lane and its attachment points are geometric conventions,
  never network nodes, transport relays or additional links.
- An unlisted edge receives no bundled geometry. Bundled paths can coincide,
  so an exact matrix or an individual selected-edge overlay is needed to inspect
  one relationship. The bundler does not remove edges to improve readability.
- The outer-lane bounds are exposed for camera fitting. World geometry caches
  survive camera pan/zoom; a topology-only change invalidates pair routes without
  rebuilding node attachments.

## Card-safe geometric routes

[`graph_routing.rs`](../crates/fhe-playground/src/graph_routing.rs) builds a shared
rectangle-corner visibility graph with six units of clearance around cards. It
returns an individual obstacle-safe polyline clipped to the source and target
card boundaries. Dense bundle attachments reuse that geometry. Both individual
and bundled paths avoid all card interiors, including endpoint reentry. Reverse
direction returns the exact reversed path.

These detours change drawing geometry only. They do not alter packet delivery,
the number of protocol hops, delay, discovery or route authorization. Invalid,
missing, overlapping or unreachable endpoints return no geometry rather than
invent a connection.

## Boundary and checks

The private binary module owns `GraphLayout`, `LayoutNode`, `LayoutEdge`, `Point`
and `Size`. It has no project-module, egui, networking or FHE dependencies.
`sync` reconciles membership and actual links; `step` advances bounded placement;
`position` and `positions` expose world centers; `settle` is useful for offline
previews. Self-links, duplicate undirected links and missing endpoints are ignored;
invalid coordinates and dimensions are sanitized before geometry is evaluated.
Node IDs must be unique within a graph update.

`GraphRouter` depends only on layout geometry; its `sync`, `route` and
`route_to_point` methods own individual visibility paths and geometric attachments.
`GraphBundler` depends on the same geometry and router; `sync` receives the complete
actual edge set, `route` returns a bundled path only for a listed edge, and `bounds`
returns the perimeter extent. These private binary modules contain no egui,
networking or FHE dependency.

Unit scenarios check different-sized coincident cards remaining disjoint through
all solver steps, retained IDs across insertion/removal, a stable settled graph,
deterministic input ordering, unfolding a crossed four-cycle, gradual reaction to
a newly established link, and finite output for invalid geometry. Dense fixtures
cover one client plus sixteen peers and eight clients plus sixteen peers. All 248
actual links in the latter fixture retain geometry clear of every card; unlisted
client/client links stay absent. Routing scenarios include collinear and multiple
blockers, all 276 pairs in a 24-card grid, reversal, cache invalidation, invalid
endpoints and blocked bundle attachments. They exercise local visual geometry and
do not assert any peer-protocol or storage guarantee.
