//! Deterministic, incremental world-space placement of a small undirected graph.
//!
//! The UI owns its camera and the protocol owns its links. This module only
//! arranges the supplied rectangles; it never adds a connection to the graph.

use std::collections::{BTreeMap, BTreeSet};

pub type NodeId = u64;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Size {
    pub width: f32,
    pub height: f32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Client,
    Peer,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LayoutNode {
    pub id: NodeId,
    pub role: NodeRole,
    pub size: Size,
    /// Initial world position for a new node; existing positions are retained.
    pub position: Option<Point>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayoutEdge {
    pub from: NodeId,
    pub to: NodeId,
}

#[derive(Clone, Copy, Debug)]
struct PlacedNode {
    role: NodeRole,
    size: Size,
    position: Point,
    anchor: Point,
}

/// Incremental spring layout with rectangle constraints and local uncrossing.
///
/// Inputs are normalized by ID, so caller iteration order does not affect the
/// layout. Each topology change retains survivors and reheats a bounded solver.
/// Call `step(1..4)` during painting, and request another frame while it is true.
#[derive(Debug, Default)]
pub struct GraphLayout {
    nodes: BTreeMap<NodeId, PlacedNode>,
    edges: Vec<(NodeId, NodeId)>,
    remaining: usize,
    dense: bool,
    ring_targets: BTreeMap<NodeId, Point>,
}

const SOLVER_STEPS: usize = 240;
const MARGIN: f32 = 24.0;
const MIN_SIZE: f32 = 8.0;

impl GraphLayout {
    /// Update actual graph membership and links, preserving surviving IDs.
    /// Duplicate edges, self-edges and dangling edges are ignored. Coordinates
    /// and dimensions are sanitized before use to keep the UI geometry finite.
    pub fn sync(&mut self, nodes: &[LayoutNode], edges: &[LayoutEdge]) -> bool {
        let specs: BTreeMap<_, _> = nodes
            .iter()
            .map(|node| {
                let mut spec = *node;
                spec.size = normalized_size(node.size);
                spec.position = node.position.and_then(normalized_point);
                (node.id, spec)
            })
            .collect();
        let links: Vec<_> = edges
            .iter()
            .filter(|edge| {
                edge.from != edge.to
                    && specs.contains_key(&edge.from)
                    && specs.contains_key(&edge.to)
            })
            .map(|edge| (edge.from.min(edge.to), edge.from.max(edge.to)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let changed = self.edges != links
            || self.nodes.len() != specs.len()
            || specs.iter().any(|(id, spec)| {
                self.nodes
                    .get(id)
                    .is_none_or(|old| old.role != spec.role || old.size != spec.size)
            });
        if !changed {
            return false;
        }

        self.nodes.retain(|id, _| specs.contains_key(id));
        for (id, spec) in specs {
            if let Some(old) = self.nodes.get_mut(&id) {
                old.role = spec.role;
                old.size = spec.size;
                old.anchor = old.position;
            } else {
                let initial = spec
                    .position
                    .unwrap_or_else(|| self.initial_position(id, spec.role, spec.size, &links));
                let position = self.nearest_free_position(initial, spec.size, id);
                self.nodes.insert(
                    id,
                    PlacedNode {
                        role: spec.role,
                        size: spec.size,
                        position,
                        anchor: position,
                    },
                );
            }
        }
        self.edges = links;
        self.remove_overlaps();
        self.dense = self.nodes.len() >= 8 && self.edges.len() >= self.nodes.len() * 2;
        self.ring_targets = if self.dense {
            self.prepare_ring()
        } else {
            BTreeMap::new()
        };
        self.remaining = if self.nodes.is_empty() {
            0
        } else {
            SOLVER_STEPS
        };
        true
    }

    /// Advance a bounded number of solver iterations. Returns whether more
    /// iterations remain. Node rectangles remain disjoint after each call.
    pub fn step(&mut self, iterations: usize) -> bool {
        for _ in 0..iterations.min(self.remaining) {
            if self.dense {
                self.relax_ring();
            } else {
                self.relax();
            }
            self.remaining -= 1;
            if !self.dense && self.remaining.is_multiple_of(24) {
                self.reduce_crossings();
            }
            if self.dense && self.remaining == 0 {
                for (id, target) in &self.ring_targets {
                    self.nodes.get_mut(id).expect("existing node").position = *target;
                }
            }
            self.remove_overlaps();
        }
        self.remaining > 0
    }

    /// Run the remaining bounded solver steps, useful for offline previews.
    pub fn settle(&mut self) {
        self.step(self.remaining);
    }

    pub fn position(&self, id: NodeId) -> Option<Point> {
        self.nodes.get(&id).map(|node| node.position)
    }

    /// Dense topology uses perimeter placement rather than spring compression.
    /// This changes geometry only; every supplied actual edge is retained.
    pub fn is_dense(&self) -> bool {
        self.dense
    }

    /// Return stable-ID-ordered node centers in world coordinates.
    pub fn positions(&self) -> Vec<(NodeId, Point)> {
        self.nodes
            .iter()
            .map(|(id, node)| (*id, node.position))
            .collect()
    }

    fn prepare_ring(&self) -> BTreeMap<NodeId, Point> {
        let center = centroid(self.nodes.values().map(|node| node.position));
        let mut ordered: Vec<_> = self
            .nodes
            .iter()
            .map(|(id, node)| {
                let relative = subtract(node.position, center);
                (*id, relative.y.atan2(relative.x))
            })
            .collect();
        ordered.sort_by(|(id_a, angle_a), (id_b, angle_b)| {
            angle_a.total_cmp(angle_b).then_with(|| id_a.cmp(id_b))
        });
        // Padded card diagonals bound the required neighbor distance regardless
        // of orientation. Equal angular spacing therefore keeps boxes disjoint.
        let diameter = self
            .nodes
            .values()
            .map(|node| (node.size.width + MARGIN).hypot(node.size.height + MARGIN))
            .fold(0.0, f32::max)
            + 2.0;
        let radius = diameter / (2.0 * (std::f32::consts::PI / ordered.len() as f32).sin());
        let phase = ordered[0].1;
        ordered
            .into_iter()
            .enumerate()
            .map(|(index, (id, _))| {
                let angle = phase + std::f32::consts::TAU * index as f32 / self.nodes.len() as f32;
                (
                    id,
                    Point {
                        x: center.x + radius * angle.cos(),
                        y: center.y + radius * angle.sin(),
                    },
                )
            })
            .collect()
    }

    fn relax_ring(&mut self) {
        let temperature = 0.15 + 0.85 * self.remaining as f32 / SOLVER_STEPS as f32;
        for (id, node) in &mut self.nodes {
            let delta = subtract(self.ring_targets[id], node.position);
            let fraction = (0.12 * temperature).max(1.0 / self.remaining as f32);
            let maximum = (14.0 * temperature).max(length(delta) / self.remaining as f32);
            node.position = add(node.position, limit_length(scale(delta, fraction), maximum));
        }
    }

    fn initial_position(
        &self,
        id: NodeId,
        role: NodeRole,
        size: Size,
        edges: &[(NodeId, NodeId)],
    ) -> Point {
        let neighbors: Vec<_> = edges
            .iter()
            .filter_map(|(a, b)| {
                let other = if *a == id {
                    *b
                } else if *b == id {
                    *a
                } else {
                    return None;
                };
                self.position(other)
            })
            .collect();
        let origin = if neighbors.is_empty() {
            Point {
                x: if role == NodeRole::Client {
                    -220.0
                } else {
                    160.0
                },
                y: 0.0,
            }
        } else {
            centroid(neighbors.iter().copied())
        };
        let angle = deterministic_angle(id);
        let radius = 120.0 + size.width * 0.5;
        Point {
            x: origin.x + angle.cos() * radius,
            y: origin.y + angle.sin() * radius,
        }
    }

    fn relax(&mut self) {
        let entries: Vec<_> = self.nodes.iter().map(|(id, node)| (*id, *node)).collect();
        let mut forces = vec![Point::default(); entries.len()];
        let indices: BTreeMap<_, _> = entries
            .iter()
            .enumerate()
            .map(|(index, (id, _))| (*id, index))
            .collect();

        for left in 0..entries.len() {
            for right in left + 1..entries.len() {
                let a = entries[left].1;
                let b = entries[right].1;
                let delta = subtract(b.position, a.position);
                let distance = length(delta).max(1.0);
                let direction = if distance <= 1.0 {
                    let angle = deterministic_angle(entries[left].0 ^ entries[right].0);
                    Point {
                        x: angle.cos(),
                        y: angle.sin(),
                    }
                } else {
                    scale(delta, 1.0 / distance)
                };
                let clearance = (a.size.width + b.size.width) * 0.5 + MARGIN;
                let repulsion = (clearance * clearance * 2.5 / (distance * distance)).min(40.0);
                let force = scale(direction, repulsion);
                forces[left] = subtract(forces[left], force);
                forces[right] = add(forces[right], force);
            }
        }
        for (from, to) in &self.edges {
            let left = indices[from];
            let right = indices[to];
            let a = entries[left].1;
            let b = entries[right].1;
            let delta = subtract(b.position, a.position);
            let distance = length(delta).max(1.0);
            let desired = (a.size.width + b.size.width) * 0.5 + 110.0;
            let attraction = (distance - desired) * 0.045;
            let force = scale(delta, attraction / distance);
            forces[left] = add(forces[left], force);
            forces[right] = subtract(forces[right], force);
        }

        // Retain the mental map rather than recentring the entire graph whenever
        // one participant joins. The anchor is renewed only on graph changes.
        let temperature = 0.15 + 0.85 * self.remaining as f32 / SOLVER_STEPS as f32;
        for ((id, node), force) in entries.into_iter().zip(forces) {
            let force = add(force, scale(subtract(node.anchor, node.position), 0.028));
            let motion = limit_length(scale(force, temperature), 10.0 * temperature);
            self.nodes.get_mut(&id).expect("existing node").position = add(node.position, motion);
        }
    }

    /// A small deterministic local search improves straight-edge crossings.
    /// Only actual crossing-edge endpoint pairs are candidates. Accept swaps
    /// solely when they reduce crossings and do not create rectangle overlaps.
    fn reduce_crossings(&mut self) {
        let mut best = self.crossing_count();
        if best == 0 {
            return;
        }
        let mut candidates = BTreeSet::new();
        'scan: for (index, &(a, b)) in self.edges.iter().enumerate() {
            for &(c, d) in self.edges.iter().skip(index + 1) {
                if self.edges_cross((a, b), (c, d)) {
                    for (from, to) in [(a, c), (a, d), (b, c), (b, d)] {
                        candidates.insert((from.min(to), from.max(to)));
                    }
                    if candidates.len() >= 24 {
                        break 'scan;
                    }
                }
            }
        }
        // The budget keeps crossing refinement suitable for a small interactive
        // graph. It is a heuristic, not a global crossing-minimum guarantee.
        for (a, b) in candidates.into_iter().take(24) {
            if self.nodes[&a].role != self.nodes[&b].role {
                continue;
            }
            let pa = self.nodes[&a].position;
            let pb = self.nodes[&b].position;
            self.nodes.get_mut(&a).expect("existing node").position = pb;
            self.nodes.get_mut(&b).expect("existing node").position = pa;
            let count = if self.has_overlaps() {
                best
            } else {
                self.crossing_count()
            };
            if count < best {
                best = count;
                // Anchor the improvement so the spring phase does not fold it
                // immediately back into the original crossing.
                self.nodes.get_mut(&a).expect("existing node").anchor = pb;
                self.nodes.get_mut(&b).expect("existing node").anchor = pa;
            } else {
                self.nodes.get_mut(&a).expect("existing node").position = pa;
                self.nodes.get_mut(&b).expect("existing node").position = pb;
            }
            if best == 0 {
                break;
            }
        }
    }

    fn crossing_count(&self) -> usize {
        let positioned_edges: Vec<_> = self
            .edges
            .iter()
            .map(|&(a, b)| (a, b, self.nodes[&a].position, self.nodes[&b].position))
            .collect();
        positioned_edges
            .iter()
            .enumerate()
            .map(|(index, edge)| {
                positioned_edges
                    .iter()
                    .skip(index + 1)
                    .filter(|other| {
                        edge.0 != other.0
                            && edge.0 != other.1
                            && edge.1 != other.0
                            && edge.1 != other.1
                            && segments_cross(edge.2, edge.3, other.2, other.3)
                    })
                    .count()
            })
            .sum()
    }

    fn edges_cross(&self, a: (NodeId, NodeId), b: (NodeId, NodeId)) -> bool {
        if a.0 == b.0 || a.0 == b.1 || a.1 == b.0 || a.1 == b.1 {
            return false;
        }
        segments_cross(
            self.nodes[&a.0].position,
            self.nodes[&a.1].position,
            self.nodes[&b.0].position,
            self.nodes[&b.1].position,
        )
    }

    fn remove_overlaps(&mut self) {
        let ids: Vec<_> = self.nodes.keys().copied().collect();
        for _ in 0..16 {
            let mut moved = false;
            for (index, &left) in ids.iter().enumerate() {
                for &right in ids.iter().skip(index + 1) {
                    let a = self.nodes[&left];
                    let b = self.nodes[&right];
                    if !rectangles_overlap(a.position, a.size, b.position, b.size) {
                        continue;
                    }
                    let delta = subtract(b.position, a.position);
                    let dx = (a.size.width + b.size.width) * 0.5 + MARGIN - delta.x.abs();
                    let dy = (a.size.height + b.size.height) * 0.5 + MARGIN - delta.y.abs();
                    let correction = if dx < dy {
                        Point {
                            x: signed_direction(delta.x) * (dx * 0.5 + 0.01),
                            y: 0.0,
                        }
                    } else {
                        Point {
                            x: 0.0,
                            y: signed_direction(delta.y) * (dy * 0.5 + 0.01),
                        }
                    };
                    self.nodes.get_mut(&left).expect("existing node").position =
                        subtract(a.position, correction);
                    self.nodes.get_mut(&right).expect("existing node").position =
                        add(b.position, correction);
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
        // Projection can stall for many coincident rectangles. A deterministic
        // nearest-free sweep guarantees a finite disjoint result on that input.
        if self.has_overlaps() {
            let old = std::mem::take(&mut self.nodes);
            for (id, mut node) in old {
                node.position = self.nearest_free_position(node.position, node.size, id);
                self.nodes.insert(id, node);
            }
        }
    }

    fn has_overlaps(&self) -> bool {
        let nodes: Vec<_> = self.nodes.values().collect();
        nodes.iter().enumerate().any(|(index, a)| {
            nodes
                .iter()
                .skip(index + 1)
                .any(|b| rectangles_overlap(a.position, a.size, b.position, b.size))
        })
    }

    fn nearest_free_position(&self, origin: Point, size: Size, id: NodeId) -> Point {
        let free = |position| {
            self.nodes
                .values()
                .all(|node| !rectangles_overlap(position, size, node.position, node.size))
        };
        if free(origin) {
            return origin;
        }
        let unit = size.width.max(size.height) + MARGIN;
        let angle = deterministic_angle(id);
        for ring in 1..=self.nodes.len() + 2 {
            let samples = ring * 12;
            for sample in 0..samples {
                let theta = angle + std::f32::consts::TAU * sample as f32 / samples as f32;
                let radius = ring as f32 * unit;
                let point = Point {
                    x: origin.x + radius * theta.cos(),
                    y: origin.y + radius * theta.sin(),
                };
                if free(point) {
                    return point;
                }
            }
        }
        // Placing beyond the rightmost padded rectangle is always feasible.
        Point {
            x: self
                .nodes
                .values()
                .map(|node| node.position.x + node.size.width * 0.5)
                .fold(origin.x, f32::max)
                + size.width * 0.5
                + MARGIN
                + 1.0,
            y: origin.y,
        }
    }
}

fn normalized_size(size: Size) -> Size {
    let normalize = |value: f32| {
        if value.is_finite() {
            value.clamp(MIN_SIZE, 2_000.0)
        } else {
            MIN_SIZE
        }
    };
    Size {
        width: normalize(size.width),
        height: normalize(size.height),
    }
}

fn normalized_point(point: Point) -> Option<Point> {
    (point.x.is_finite() && point.y.is_finite()).then_some(Point {
        x: point.x.clamp(-100_000.0, 100_000.0),
        y: point.y.clamp(-100_000.0, 100_000.0),
    })
}

fn deterministic_angle(id: NodeId) -> f32 {
    let hash = id.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (hash >> 32) as f32 / u32::MAX as f32 * std::f32::consts::TAU
}

fn rectangles_overlap(a: Point, sa: Size, b: Point, sb: Size) -> bool {
    (a.x - b.x).abs() < (sa.width + sb.width) * 0.5 + MARGIN - 0.001
        && (a.y - b.y).abs() < (sa.height + sb.height) * 0.5 + MARGIN - 0.001
}

fn add(a: Point, b: Point) -> Point {
    Point {
        x: a.x + b.x,
        y: a.y + b.y,
    }
}

fn subtract(a: Point, b: Point) -> Point {
    Point {
        x: a.x - b.x,
        y: a.y - b.y,
    }
}

fn scale(a: Point, factor: f32) -> Point {
    Point {
        x: a.x * factor,
        y: a.y * factor,
    }
}

fn length(a: Point) -> f32 {
    a.x.hypot(a.y)
}

fn limit_length(a: Point, maximum: f32) -> Point {
    let magnitude = length(a);
    if magnitude > maximum {
        scale(a, maximum / magnitude)
    } else {
        a
    }
}

fn centroid(points: impl Iterator<Item = Point>) -> Point {
    let (total, count) = points.fold((Point::default(), 0), |(sum, count), p| {
        (add(sum, p), count + 1)
    });
    if count == 0 {
        Point::default()
    } else {
        scale(total, 1.0 / count as f32)
    }
}

fn signed_direction(value: f32) -> f32 {
    if value < 0.0 { -1.0 } else { 1.0 }
}

fn segments_cross(a: Point, b: Point, c: Point, d: Point) -> bool {
    let side = |a: Point, b: Point, p: Point| (b.x - a.x) * (p.y - a.y) - (b.y - a.y) * (p.x - a.x);
    side(a, b, c) * side(a, b, d) < -0.01 && side(c, d, a) * side(c, d, b) < -0.01
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: NodeId, x: f32, y: f32) -> LayoutNode {
        LayoutNode {
            id,
            role: NodeRole::Peer,
            size: Size {
                width: 140.0,
                height: 72.0,
            },
            position: Some(Point { x, y }),
        }
    }

    fn assert_rectangles_disjoint(layout: &GraphLayout, nodes: &[LayoutNode]) {
        for (index, a) in nodes.iter().enumerate() {
            let pa = layout.position(a.id).expect("node retained");
            assert!(pa.x.is_finite() && pa.y.is_finite(), "finite node {}", a.id);
            for b in nodes.iter().skip(index + 1) {
                let pb = layout.position(b.id).expect("node retained");
                assert!(
                    (pa.x - pb.x).abs() >= (a.size.width + b.size.width) * 0.5
                        || (pa.y - pb.y).abs() >= (a.size.height + b.size.height) * 0.5,
                    "nodes {} and {} overlap: {pa:?}, {pb:?}",
                    a.id,
                    b.id
                );
            }
        }
    }

    #[test]
    fn coincident_nodes_have_disjoint_rectangles_throughout_relaxation() {
        let nodes: Vec<_> = (0..48)
            .map(|id| {
                let mut node = peer(id, 0.0, 0.0);
                node.size.width = 90.0 + (id % 8) as f32 * 40.0;
                node.size.height = 50.0 + (id % 4) as f32 * 24.0;
                node
            })
            .collect();
        let edges: Vec<_> = (1..48)
            .map(|id| LayoutEdge {
                from: id - 1,
                to: id,
            })
            .collect();
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &edges);

        while layout.step(4) {
            assert_rectangles_disjoint(&layout, &nodes);
        }

        assert_rectangles_disjoint(&layout, &nodes);
    }

    #[test]
    fn surviving_ids_keep_world_positions_when_membership_changes() {
        let mut nodes = vec![peer(10, -200.0, 0.0), peer(20, 200.0, 0.0)];
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &[LayoutEdge { from: 10, to: 20 }]);
        layout.settle();
        let survivors = layout.positions();
        nodes.push(peer(30, 800.0, 0.0));

        layout.sync(&nodes, &[LayoutEdge { from: 10, to: 20 }]);

        for (id, position) in survivors {
            assert_eq!(layout.position(id), Some(position));
        }
        let before_removal = layout.position(20);
        nodes.retain(|node| node.id != 10);
        layout.sync(&nodes, &[]);
        assert_eq!(layout.position(20), before_removal);
        assert_eq!(layout.position(10), None);
    }

    #[test]
    fn unchanged_topology_does_not_restart_or_move_a_settled_layout() {
        let nodes = vec![peer(1, -200.0, 0.0), peer(2, 200.0, 0.0)];
        let edges = [LayoutEdge { from: 1, to: 2 }];
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &edges);
        layout.settle();
        let positions = layout.positions();

        assert!(!layout.sync(&nodes, &edges));

        assert!(!layout.step(4));
        assert_eq!(layout.positions(), positions);
    }

    #[test]
    fn input_order_and_edge_direction_do_not_change_placement() {
        let nodes = vec![
            peer(1, -240.0, 0.0),
            peer(2, 240.0, 0.0),
            peer(3, 0.0, 240.0),
        ];
        let edges = [LayoutEdge { from: 1, to: 2 }, LayoutEdge { from: 2, to: 3 }];
        let mut first = GraphLayout::default();
        first.sync(&nodes, &edges);
        first.settle();
        let reversed_nodes: Vec<_> = nodes.iter().rev().copied().collect();
        let reversed_edges: Vec<_> = edges
            .iter()
            .rev()
            .map(|edge| LayoutEdge {
                from: edge.to,
                to: edge.from,
            })
            .collect();
        let mut second = GraphLayout::default();

        second.sync(&reversed_nodes, &reversed_edges);
        second.settle();

        assert_eq!(first.positions(), second.positions());
    }

    #[test]
    fn a_crossed_cycle_unfolds_without_overlapping_nodes() {
        let nodes = [
            peer(1, -220.0, -180.0),
            peer(2, 220.0, 180.0),
            peer(3, -220.0, 180.0),
            peer(4, 220.0, -180.0),
        ];
        let edges = [
            LayoutEdge { from: 1, to: 2 },
            LayoutEdge { from: 2, to: 3 },
            LayoutEdge { from: 3, to: 4 },
            LayoutEdge { from: 4, to: 1 },
        ];
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &edges);

        layout.settle();

        // A consistently oriented convex cycle has no crossed opposite edges.
        // Assert the observable polygon through the public world coordinates.
        let cycle: Vec<_> = (1..=4).map(|id| layout.position(id).unwrap()).collect();
        let turns: Vec<_> = (0..4)
            .map(|index| {
                let a = cycle[index];
                let b = cycle[(index + 1) % 4];
                let c = cycle[(index + 2) % 4];
                (b.x - a.x) * (c.y - b.y) - (b.y - a.y) * (c.x - b.x)
            })
            .collect();
        assert!(turns.iter().all(|turn| *turn > 0.0) || turns.iter().all(|turn| *turn < 0.0));
        assert_rectangles_disjoint(&layout, &nodes);
    }

    #[test]
    fn newly_established_link_moves_nodes_gradually_toward_each_other() {
        let mut client = peer(1, -500.0, 0.0);
        client.role = NodeRole::Client;
        let nodes = [client, peer(2, 500.0, 0.0)];
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &[]);
        layout.settle();
        let before = layout.positions();
        let old_distance = length(subtract(before[0].1, before[1].1));

        layout.sync(&nodes, &[LayoutEdge { from: 1, to: 2 }]);
        layout.step(1);

        for (id, position) in before {
            assert!(length(subtract(layout.position(id).unwrap(), position)) <= 10.01);
        }
        layout.settle();
        let new_distance = length(subtract(
            layout.position(1).unwrap(),
            layout.position(2).unwrap(),
        ));
        assert!(
            new_distance < old_distance * 0.6,
            "actual link should attract endpoints"
        );
        assert_rectangles_disjoint(&layout, &nodes);
    }

    #[test]
    fn malformed_geometry_and_dangling_links_produce_finite_positions() {
        let mut invalid = peer(2, f32::NAN, f32::INFINITY);
        invalid.size = Size {
            width: f32::INFINITY,
            height: -10.0,
        };
        let mut layout = GraphLayout::default();
        layout.sync(
            &[peer(1, 0.0, 0.0), invalid],
            &[LayoutEdge { from: 1, to: 9 }, LayoutEdge { from: 2, to: 2 }],
        );

        layout.settle();

        assert!(
            layout
                .positions()
                .iter()
                .all(|(_, point)| point.x.is_finite() && point.y.is_finite())
        );
        assert_eq!(
            layout
                .positions()
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    fn dense_graph(clients: usize, peers: usize) -> (Vec<LayoutNode>, Vec<LayoutEdge>) {
        let nodes: Vec<_> = (0..clients + peers)
            .map(|id| {
                let mut node = peer(id as u64, 0.0, 0.0);
                if id < clients {
                    node.role = NodeRole::Client;
                }
                node
            })
            .collect();
        let edges = (0..nodes.len())
            .flat_map(|a| {
                (a + 1..nodes.len())
                    .filter(move |b| a >= clients || *b >= clients)
                    .map(move |b| LayoutEdge {
                        from: a as u64,
                        to: b as u64,
                    })
            })
            .collect();
        (nodes, edges)
    }

    #[test]
    fn dense_peer_mesh_places_every_card_on_a_clear_outer_ring() {
        for (clients, peers) in [(1, 16), (8, 16)] {
            let (nodes, edges) = dense_graph(clients, peers);
            let mut layout = GraphLayout::default();
            layout.sync(&nodes, &edges);
            assert!(layout.is_dense());
            while layout.step(3) {
                assert_rectangles_disjoint(&layout, &nodes);
            }

            assert_rectangles_disjoint(&layout, &nodes);
            let points = layout.positions();
            let center = Point {
                x: points.iter().map(|(_, p)| p.x).sum::<f32>() / points.len() as f32,
                y: points.iter().map(|(_, p)| p.y).sum::<f32>() / points.len() as f32,
            };
            let radius = length(subtract(points[0].1, center));
            assert!(
                points
                    .iter()
                    .all(|(_, point)| (length(subtract(*point, center)) - radius).abs() < 0.01)
            );
            assert_eq!(points.len(), clients + peers);
            let mut reordered = GraphLayout::default();
            reordered.sync(
                &nodes.iter().rev().copied().collect::<Vec<_>>(),
                &edges.iter().rev().copied().collect::<Vec<_>>(),
            );
            reordered.settle();
            assert_eq!(reordered.positions(), points);
        }
    }

    #[test]
    fn a_dense_update_keeps_survivors_and_an_explicit_new_seed_until_stepping() {
        let (mut nodes, mut edges) = dense_graph(1, 16);
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &edges);
        layout.settle();
        let old = layout.positions();
        let new = peer(99, 2500.0, 1200.0);
        nodes.push(new);
        edges.push(LayoutEdge { from: 0, to: 99 });

        layout.sync(&nodes, &edges);

        for (id, position) in old {
            assert_eq!(layout.position(id), Some(position));
        }
        assert_eq!(layout.position(99), new.position);
        layout.settle();
        assert_rectangles_disjoint(&layout, &nodes);
    }

    #[test]
    fn a_large_sparse_chain_keeps_the_dynamic_spring_layout() {
        let nodes: Vec<_> = (0..16).map(|id| peer(id, id as f32 * 180.0, 0.0)).collect();
        let edges: Vec<_> = (1..16)
            .map(|id| LayoutEdge {
                from: id - 1,
                to: id,
            })
            .collect();
        let mut layout = GraphLayout::default();

        layout.sync(&nodes, &edges);
        layout.settle();

        assert!(!layout.is_dense());
        assert_rectangles_disjoint(&layout, &nodes);
    }
}
