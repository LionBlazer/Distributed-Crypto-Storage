//! Geometric paths for actual protocol links; detours are never protocol hops.

use std::collections::BTreeMap;

use crate::graph_layout::{NodeId, Point, Size};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RouteNode {
    pub id: NodeId,
    pub center: Point,
    pub size: Size,
}

/// Cached rectangle-corner visibility routing for the small local network map.
/// World geometry is independent of the camera, packets, and graph membership.
#[derive(Default)]
pub struct GraphRouter {
    nodes: BTreeMap<NodeId, RouteNode>,
    corners: Vec<Point>,
    adjacency: Vec<Vec<(usize, f32)>>,
    terminals: BTreeMap<NodeId, Vec<(usize, f32)>>,
    routes: BTreeMap<(NodeId, NodeId), Vec<Point>>,
}

const CLEARANCE: f32 = 6.0;
const EPSILON: f32 = 0.001;

impl GraphRouter {
    /// Rebuild visibility and invalidate routes only when world geometry changes.
    /// Non-finite coordinates, non-positive dimensions and excessive geometry
    /// are ignored. IDs must be unique; input order otherwise does not matter.
    pub fn sync(&mut self, nodes: &[RouteNode]) -> bool {
        let next: BTreeMap<_, _> = nodes
            .iter()
            .copied()
            .filter(valid_node)
            .map(|node| (node.id, node))
            .collect();
        if next == self.nodes {
            return false;
        }
        self.nodes = next;
        self.routes.clear();
        self.corners.clear();
        for node in self.nodes.values() {
            self.corners.extend(corners(*node));
        }
        self.adjacency = vec![Vec::new(); self.corners.len()];
        for left in 0..self.corners.len() {
            for right in left + 1..self.corners.len() {
                let a = self.corners[left];
                let b = self.corners[right];
                if self.clear_segment(a, b, None, None) {
                    let weight = distance(a, b);
                    self.adjacency[left].push((right, weight));
                    self.adjacency[right].push((left, weight));
                }
            }
        }
        self.terminals = self
            .nodes
            .values()
            .map(|node| {
                let visible = self
                    .corners
                    .iter()
                    .enumerate()
                    .filter(|(_, point)| {
                        self.clear_segment(node.center, **point, Some(node.id), None)
                    })
                    .map(|(index, point)| (index, distance(node.center, *point)))
                    .collect();
                (node.id, visible)
            })
            .collect();
        true
    }

    /// Path from source card boundary to target card boundary, or an empty path
    /// for missing/self IDs, overlapping endpoints or blocked geometry. Calling
    /// this method does not establish a link; the caller supplies actual links.
    /// Opposite directions share one cached route and are exact reversals.
    pub fn route(&mut self, from: NodeId, to: NodeId) -> Vec<Point> {
        if from == to || !self.nodes.contains_key(&from) || !self.nodes.contains_key(&to) {
            return Vec::new();
        }
        let key = (from.min(to), from.max(to));
        if !self.routes.contains_key(&key) {
            let path = self.find_route(key.0, key.1);
            self.routes.insert(key, path);
        }
        let mut path = self.routes[&key].clone();
        if from > to {
            path.reverse();
        }
        path
    }

    /// Geometric attachment to an unoccupied world point, useful for visual
    /// bundle lanes. The point is not a protocol node or a transport hop.
    pub fn route_to_point(&self, from: NodeId, target: Point) -> Vec<Point> {
        let Some(source) = self.nodes.get(&from).copied() else {
            return Vec::new();
        };
        if !target.x.is_finite()
            || !target.y.is_finite()
            || self
                .nodes
                .values()
                .any(|node| segment_intersects_rectangle(target, target, *node, 0.0))
        {
            return Vec::new();
        }
        if self.clear_segment(source.center, target, Some(from), None) {
            return vec![boundary_toward(source, target), target];
        }
        let target_costs: Vec<_> = self
            .corners
            .iter()
            .map(|corner| {
                if self.clear_segment(*corner, target, None, None) {
                    distance(*corner, target)
                } else {
                    f32::INFINITY
                }
            })
            .collect();
        let mut path = self.corner_path(from, target, &target_costs);
        if path.len() > 1 {
            path[0] = boundary_toward(source, path[1]);
        }
        path
    }

    fn find_route(&self, from: NodeId, to: NodeId) -> Vec<Point> {
        let a = self.nodes[&from];
        let b = self.nodes[&to];
        if rectangles_overlap(a, b) {
            return Vec::new();
        }
        if self.clear_segment(a.center, b.center, Some(from), Some(to)) {
            return vec![boundary_toward(a, b.center), boundary_toward(b, a.center)];
        }

        let mut target_costs = vec![f32::INFINITY; self.corners.len()];
        for &(index, cost) in &self.terminals[&to] {
            target_costs[index] = cost;
        }
        let mut path = self.corner_path(from, b.center, &target_costs);
        if path.len() > 1 {
            path[0] = boundary_toward(a, path[1]);
            let last = path.len() - 1;
            path[last] = boundary_toward(b, path[last - 1]);
        }
        path
    }

    fn corner_path(&self, from: NodeId, target: Point, target_costs: &[f32]) -> Vec<Point> {
        // Shared visibility and terminal connections are built once per geometry
        // rather than rebuilding a complete graph for each protocol connection.
        let mut distances = vec![f32::INFINITY; self.corners.len()];
        let mut parents = vec![None; self.corners.len()];
        let mut visited = vec![false; self.corners.len()];
        for &(index, cost) in &self.terminals[&from] {
            distances[index] = cost;
        }
        let mut best = f32::INFINITY;
        let mut last = None;
        for _ in 0..self.corners.len() {
            let current = (0..self.corners.len())
                .filter(|index| !visited[*index])
                .min_by(|left, right| distances[*left].total_cmp(&distances[*right]));
            let Some(current) = current else {
                break;
            };
            if distances[current] >= best {
                break;
            }
            visited[current] = true;
            let complete = distances[current] + target_costs[current];
            if complete < best {
                best = complete;
                last = Some(current);
            }
            for &(next, weight) in &self.adjacency[current] {
                let candidate = distances[current] + weight;
                if candidate < distances[next] {
                    distances[next] = candidate;
                    parents[next] = Some(current);
                }
            }
        }
        let Some(mut current) = last else {
            return Vec::new();
        };
        let mut path = vec![target];
        loop {
            path.push(self.corners[current]);
            if let Some(previous) = parents[current] {
                current = previous;
            } else {
                break;
            }
        }
        path.push(self.nodes[&from].center);
        path.reverse();
        path
    }

    fn clear_segment(
        &self,
        a: Point,
        b: Point,
        exclude_a: Option<NodeId>,
        exclude_b: Option<NodeId>,
    ) -> bool {
        self.nodes.values().all(|node| {
            Some(node.id) == exclude_a
                || Some(node.id) == exclude_b
                || !segment_intersects_rectangle(a, b, *node, CLEARANCE)
        })
    }
}

pub(crate) fn valid_node(node: &RouteNode) -> bool {
    node.center.x.is_finite()
        && node.center.y.is_finite()
        && node.center.x.abs() <= 1_000_000.0
        && node.center.y.abs() <= 1_000_000.0
        && node.size.width.is_finite()
        && node.size.height.is_finite()
        && node.size.width > 0.0
        && node.size.height > 0.0
        && node.size.width <= 10_000.0
        && node.size.height <= 10_000.0
}

fn corners(node: RouteNode) -> [Point; 4] {
    let x = node.size.width * 0.5 + CLEARANCE;
    let y = node.size.height * 0.5 + CLEARANCE;
    [
        Point {
            x: node.center.x - x,
            y: node.center.y - y,
        },
        Point {
            x: node.center.x + x,
            y: node.center.y - y,
        },
        Point {
            x: node.center.x + x,
            y: node.center.y + y,
        },
        Point {
            x: node.center.x - x,
            y: node.center.y + y,
        },
    ]
}

fn rectangles_overlap(a: RouteNode, b: RouteNode) -> bool {
    (a.center.x - b.center.x).abs() < (a.size.width + b.size.width) * 0.5
        && (a.center.y - b.center.y).abs() < (a.size.height + b.size.height) * 0.5
}

fn boundary_toward(node: RouteNode, point: Point) -> Point {
    let dx = point.x - node.center.x;
    let dy = point.y - node.center.y;
    let scale = (node.size.width * 0.5 / dx.abs().max(EPSILON))
        .min(node.size.height * 0.5 / dy.abs().max(EPSILON));
    Point {
        x: node.center.x + dx * scale,
        y: node.center.y + dy * scale,
    }
}

fn distance(a: Point, b: Point) -> f32 {
    (a.x - b.x).hypot(a.y - b.y)
}

/// Slab clipping against the open interior of an inflated rectangle. Tangency
/// and travel along its boundary are allowed; corners form visibility vertices.
fn segment_intersects_rectangle(a: Point, b: Point, node: RouteNode, padding: f32) -> bool {
    let half_x = (node.size.width * 0.5 + padding - EPSILON).max(0.0);
    let half_y = (node.size.height * 0.5 + padding - EPSILON).max(0.0);
    let mut enter: f32 = 0.0;
    let mut leave: f32 = 1.0;
    for (origin, delta, min, max) in [
        (
            a.x,
            b.x - a.x,
            node.center.x - half_x,
            node.center.x + half_x,
        ),
        (
            a.y,
            b.y - a.y,
            node.center.y - half_y,
            node.center.y + half_y,
        ),
    ] {
        if delta.abs() < EPSILON {
            if origin <= min || origin >= max {
                return false;
            }
        } else {
            let first = (min - origin) / delta;
            let second = (max - origin) / delta;
            enter = enter.max(first.min(second));
            leave = leave.min(first.max(second));
            if enter >= leave {
                return false;
            }
        }
    }
    enter < leave
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: NodeId, x: f32, y: f32) -> RouteNode {
        RouteNode {
            id,
            center: Point { x, y },
            size: Size {
                width: 100.0,
                height: 60.0,
            },
        }
    }

    fn assert_path_clear(path: &[Point], nodes: &[RouteNode]) {
        assert!(path.len() >= 2, "route must exist");
        assert!(
            path.iter()
                .all(|point| point.x.is_finite() && point.y.is_finite())
        );
        // Independently sample segment interiors, including endpoints, against
        // every rendered card rather than inspecting router caches or slabs.
        for segment in path.windows(2) {
            for sample in 0..=500 {
                let t = sample as f32 / 500.0;
                let x = segment[0].x + (segment[1].x - segment[0].x) * t;
                let y = segment[0].y + (segment[1].y - segment[0].y) * t;
                for node in nodes {
                    assert!(
                        (x - node.center.x).abs() >= node.size.width * 0.5 - 0.001
                            || (y - node.center.y).abs() >= node.size.height * 0.5 - 0.001,
                        "segment crossed card {} at ({x}, {y})",
                        node.id
                    );
                }
            }
        }
    }

    #[test]
    fn a_clear_link_uses_its_two_card_boundaries_without_a_detour() {
        let nodes = [card(1, -200.0, 0.0), card(2, 200.0, 0.0)];
        let mut router = GraphRouter::default();
        router.sync(&nodes);

        let route = router.route(1, 2);

        assert_eq!(
            route,
            [Point { x: -150.0, y: 0.0 }, Point { x: 150.0, y: 0.0 }]
        );
        assert_path_clear(&route, &nodes);
    }

    #[test]
    fn an_outer_link_detours_around_a_collinear_middle_card() {
        let nodes = [card(1, -240.0, 0.0), card(2, 240.0, 0.0), card(3, 0.0, 0.0)];
        let mut router = GraphRouter::default();
        router.sync(&nodes);

        let route = router.route(1, 2);

        assert!(route.iter().any(|point| point.y.abs() >= 36.0));
        assert_path_clear(&route, &nodes);
    }

    #[test]
    fn multiple_blockers_have_a_clear_deterministic_route() {
        let nodes = [
            card(1, -400.0, 0.0),
            card(2, 400.0, 0.0),
            card(3, -100.0, -15.0),
            card(4, 100.0, 15.0),
            card(5, 0.0, -150.0),
        ];
        let mut first = GraphRouter::default();
        first.sync(&nodes);
        let mut second = GraphRouter::default();
        let reordered: Vec<_> = nodes.iter().rev().copied().collect();
        second.sync(&reordered);

        let route = first.route(1, 2);

        assert_eq!(route, second.route(1, 2));
        assert_path_clear(&route, &nodes);
    }

    #[test]
    fn reverse_direction_follows_exactly_the_same_geometric_path() {
        let nodes = [card(1, -240.0, 0.0), card(2, 240.0, 0.0), card(3, 0.0, 0.0)];
        let mut router = GraphRouter::default();
        router.sync(&nodes);
        let forward = router.route(1, 2);

        let reverse = router.route(2, 1);

        assert_eq!(reverse, forward.into_iter().rev().collect::<Vec<_>>());
    }

    #[test]
    fn moving_a_blocker_invalidates_the_previous_detour() {
        let mut nodes = [card(1, -240.0, 0.0), card(2, 240.0, 0.0), card(3, 0.0, 0.0)];
        let mut router = GraphRouter::default();
        router.sync(&nodes);
        assert!(router.route(1, 2).len() > 2);
        nodes[2].center.y = 200.0;

        assert!(router.sync(&nodes));

        assert_eq!(router.route(1, 2).len(), 2);
        assert!(!router.sync(&nodes));
    }

    #[test]
    fn missing_invalid_and_overlapping_endpoints_have_no_route() {
        let mut invalid = card(3, f32::NAN, 0.0);
        invalid.size.height = -2.0;
        let mut router = GraphRouter::default();
        router.sync(&[card(1, 0.0, 0.0), card(2, 20.0, 0.0), invalid]);

        assert!(router.route(1, 1).is_empty());
        assert!(router.route(1, 2).is_empty());
        assert!(router.route(1, 3).is_empty());
        assert!(router.route(1, 99).is_empty());
    }

    #[test]
    fn every_pair_in_a_24_card_grid_has_a_clear_route() {
        let nodes: Vec<_> = (0..24)
            .map(|id| card(id, (id % 6) as f32 * 160.0, (id / 6) as f32 * 120.0))
            .collect();
        let mut router = GraphRouter::default();
        router.sync(&nodes);

        for (index, from) in nodes.iter().enumerate() {
            for to in nodes.iter().skip(index + 1) {
                let path = router.route(from.id, to.id);
                assert_path_clear(&path, &nodes);
            }
        }
    }

    #[test]
    fn an_attachment_to_a_world_lane_avoids_blockers_and_rejects_occupied_points() {
        let nodes = [card(1, -240.0, 0.0), card(2, 0.0, 0.0), card(3, 120.0, 0.0)];
        let mut router = GraphRouter::default();
        router.sync(&nodes);
        let target = Point { x: 400.0, y: 0.0 };

        let route = router.route_to_point(1, target);

        assert_eq!(route.last(), Some(&target));
        assert_path_clear(&route, &nodes);
        assert!(router.route_to_point(1, nodes[1].center).is_empty());
        assert!(router.route_to_point(99, target).is_empty());
        assert!(
            router
                .route_to_point(
                    1,
                    Point {
                        x: f32::NAN,
                        y: 0.0
                    }
                )
                .is_empty()
        );
    }
}
