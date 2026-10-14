//! Shared geometric lanes for dense diagrams, never invented protocol hops.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph_layout::{LayoutEdge, NodeId, Point};
use crate::graph_routing::{GraphRouter, RouteNode, valid_node};

#[derive(Clone, Copy)]
struct Perimeter {
    min: Point,
    max: Point,
}

/// Preserves every supplied actual link while sharing outer geometric lanes.
/// Matrix inspection or a highlighted individual route disambiguates coincident
/// bundles; a lane is a drawing convention, not a relay, peer or network link.
#[derive(Default)]
pub struct GraphBundler {
    nodes: BTreeMap<NodeId, RouteNode>,
    links: BTreeSet<(NodeId, NodeId)>,
    router: GraphRouter,
    perimeter: Option<Perimeter>,
    attachments: BTreeMap<NodeId, Vec<Point>>,
    routes: BTreeMap<(NodeId, NodeId), Vec<Point>>,
}

impl GraphBundler {
    /// Update world geometry and the complete actual undirected edge set.
    /// Geometry is independent of the camera. Geometry changes rebuild shared
    /// node attachments; topology-only updates invalidate just the pair cache.
    pub fn sync(&mut self, nodes: &[RouteNode], links: &[LayoutEdge]) -> bool {
        let next: BTreeMap<_, _> = nodes
            .iter()
            .copied()
            .filter(valid_node)
            .map(|node| (node.id, node))
            .collect();
        let next_links: BTreeSet<_> = links
            .iter()
            .filter(|edge| {
                edge.from != edge.to && next.contains_key(&edge.from) && next.contains_key(&edge.to)
            })
            .map(|edge| (edge.from.min(edge.to), edge.from.max(edge.to)))
            .collect();
        let geometry_changed = next != self.nodes;
        if !geometry_changed && next_links == self.links {
            return false;
        }
        self.links = next_links;
        self.routes.clear();
        if geometry_changed {
            self.nodes = next;
            let nodes: Vec<_> = self.nodes.values().copied().collect();
            self.router.sync(&nodes);
            self.perimeter = perimeter(&nodes);
            self.attachments.clear();
            if let Some(lane) = self.perimeter {
                for node in &nodes {
                    let port = lane.nearest_port(node.center);
                    let path = self.router.route_to_point(node.id, port);
                    self.attachments.insert(node.id, path);
                }
            }
        }
        true
    }

    /// Route one supplied actual link along shared outer lanes. Unlisted links
    /// produce no geometry. Reversed direction exactly reverses the same path.
    pub fn route(&mut self, from: NodeId, to: NodeId) -> Vec<Point> {
        let key = (from.min(to), from.max(to));
        if !self.links.contains(&key) {
            return Vec::new();
        }
        if !self.routes.contains_key(&key) {
            let path = self.bundle(key.0, key.1);
            self.routes.insert(key, path);
        }
        let mut route = self.routes[&key].clone();
        if from > to {
            route.reverse();
        }
        route
    }

    /// Outer lane bounds for camera fitting, including the six-unit attachment
    /// router clearance and the larger perimeter margin around every card.
    pub fn bounds(&self) -> Option<(Point, Point)> {
        self.perimeter.map(|lane| (lane.min, lane.max))
    }

    fn bundle(&self, from: NodeId, to: NodeId) -> Vec<Point> {
        let Some(lane) = self.perimeter else {
            return Vec::new();
        };
        let Some(a) = self.attachments.get(&from).filter(|path| path.len() > 1) else {
            return Vec::new();
        };
        let Some(b) = self.attachments.get(&to).filter(|path| path.len() > 1) else {
            return Vec::new();
        };
        let middle = lane.shortest_path(*a.last().unwrap(), *b.last().unwrap());
        let mut path = a.clone();
        path.extend(middle.into_iter().skip(1));
        path.extend(b.iter().rev().skip(1).copied());
        path.dedup_by(|left, right| distance(*left, *right) < 0.001);
        path
    }
}

fn perimeter(nodes: &[RouteNode]) -> Option<Perimeter> {
    if nodes.is_empty() {
        return None;
    }
    let mut min = Point {
        x: f32::INFINITY,
        y: f32::INFINITY,
    };
    let mut max = Point {
        x: f32::NEG_INFINITY,
        y: f32::NEG_INFINITY,
    };
    for node in nodes {
        min.x = min.x.min(node.center.x - node.size.width * 0.5 - 56.0);
        min.y = min.y.min(node.center.y - node.size.height * 0.5 - 56.0);
        max.x = max.x.max(node.center.x + node.size.width * 0.5 + 56.0);
        max.y = max.y.max(node.center.y + node.size.height * 0.5 + 56.0);
    }
    Some(Perimeter { min, max })
}

impl Perimeter {
    fn nearest_port(self, point: Point) -> Point {
        [
            Point {
                x: self.min.x,
                y: point.y,
            },
            Point {
                x: self.max.x,
                y: point.y,
            },
            Point {
                x: point.x,
                y: self.min.y,
            },
            Point {
                x: point.x,
                y: self.max.y,
            },
        ]
        .into_iter()
        .min_by(|a, b| distance(*a, point).total_cmp(&distance(*b, point)))
        .unwrap()
    }

    fn width(self) -> f32 {
        self.max.x - self.min.x
    }
    fn height(self) -> f32 {
        self.max.y - self.min.y
    }

    fn parameter(self, point: Point) -> f32 {
        let width = self.width();
        let height = self.height();
        if (point.y - self.min.y).abs() < 0.001 {
            point.x - self.min.x
        } else if (point.x - self.max.x).abs() < 0.001 {
            width + point.y - self.min.y
        } else if (point.y - self.max.y).abs() < 0.001 {
            width + height + self.max.x - point.x
        } else {
            width * 2.0 + height + self.max.y - point.y
        }
    }

    fn shortest_path(self, from: Point, to: Point) -> Vec<Point> {
        let total = (self.width() + self.height()) * 2.0;
        let clockwise = (self.parameter(to) - self.parameter(from)).rem_euclid(total);
        if clockwise <= total * 0.5 {
            self.clockwise_path(from, to)
        } else {
            let mut path = self.clockwise_path(to, from);
            path.reverse();
            path
        }
    }

    fn clockwise_path(self, from: Point, to: Point) -> Vec<Point> {
        let width = self.width();
        let height = self.height();
        let total = (width + height) * 2.0;
        let start = self.parameter(from);
        let end = start + (self.parameter(to) - start).rem_euclid(total);
        let corners = [
            (
                width,
                Point {
                    x: self.max.x,
                    y: self.min.y,
                },
            ),
            (width + height, self.max),
            (
                width * 2.0 + height,
                Point {
                    x: self.min.x,
                    y: self.max.y,
                },
            ),
            (total, self.min),
        ];
        let mut path = vec![from];
        for turn in 0..=1 {
            for (parameter, point) in corners {
                let parameter = parameter + turn as f32 * total;
                if parameter > start + 0.001 && parameter < end - 0.001 {
                    path.push(point);
                }
            }
        }
        path.push(to);
        path
    }
}

fn distance(a: Point, b: Point) -> f32 {
    (a.x - b.x).hypot(a.y - b.y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_layout::{GraphLayout, LayoutNode, NodeRole, Size};

    fn dense_cards(clients: usize, peers: usize) -> (Vec<RouteNode>, Vec<LayoutEdge>) {
        let nodes: Vec<_> = (0..clients + peers)
            .map(|id| LayoutNode {
                id: id as u64,
                role: if id < clients {
                    NodeRole::Client
                } else {
                    NodeRole::Peer
                },
                size: Size {
                    width: 148.0,
                    height: 78.0,
                },
                position: None,
            })
            .collect();
        let edges: Vec<_> = (0..nodes.len())
            .flat_map(|a| {
                (a + 1..nodes.len())
                    .filter(move |b| a >= clients || *b >= clients)
                    .map(move |b| LayoutEdge {
                        from: a as u64,
                        to: b as u64,
                    })
            })
            .collect();
        let mut layout = GraphLayout::default();
        layout.sync(&nodes, &edges);
        layout.settle();
        (
            nodes
                .iter()
                .map(|node| RouteNode {
                    id: node.id,
                    center: layout.position(node.id).unwrap(),
                    size: node.size,
                })
                .collect(),
            edges,
        )
    }

    fn assert_clear(path: &[Point], nodes: &[RouteNode]) {
        assert!(path.len() >= 2);
        for segment in path.windows(2) {
            for sample in 0..=180 {
                let t = sample as f32 / 180.0;
                let x = segment[0].x + (segment[1].x - segment[0].x) * t;
                let y = segment[0].y + (segment[1].y - segment[0].y) * t;
                assert!(x.is_finite() && y.is_finite());
                for node in nodes {
                    assert!(
                        (x - node.center.x).abs() >= node.size.width * 0.5 - 0.001
                            || (y - node.center.y).abs() >= node.size.height * 0.5 - 0.001,
                        "path reentered card {} at ({x},{y})",
                        node.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_actual_link_in_a_24_node_dense_graph_remains_present_and_clear() {
        let (nodes, edges) = dense_cards(8, 16);
        let mut bundler = GraphBundler::default();
        bundler.sync(&nodes, &edges);
        let (min, max) = bundler.bounds().unwrap();

        for edge in &edges {
            let route = bundler.route(edge.from, edge.to);
            assert_clear(&route, &nodes);
            assert!(route.iter().all(|p| p.x >= min.x - 0.001
                && p.x <= max.x + 0.001
                && p.y >= min.y - 0.001
                && p.y <= max.y + 0.001));
        }
        assert_eq!(edges.len(), 248);
        assert!(
            bundler.route(0, 1).is_empty(),
            "unlisted client/client link must stay absent"
        );
    }

    #[test]
    fn reverse_direction_and_input_order_preserve_geometric_path() {
        let (nodes, edges) = dense_cards(1, 16);
        let mut first = GraphBundler::default();
        first.sync(&nodes, &edges);
        let route = first.route(0, 12);
        let reverse = first.route(12, 0);
        let mut second = GraphBundler::default();
        second.sync(
            &nodes.iter().rev().copied().collect::<Vec<_>>(),
            &edges.iter().rev().copied().collect::<Vec<_>>(),
        );

        assert_eq!(reverse, route.iter().rev().copied().collect::<Vec<_>>());
        assert_eq!(second.route(0, 12), route);
        assert!(!first.sync(&nodes, &edges));
        assert_clear(&route, &nodes);
    }

    #[test]
    fn adding_a_link_does_not_fabricate_other_links_and_removing_it_clears_its_route() {
        let (nodes, _) = dense_cards(1, 16);
        let edge = LayoutEdge { from: 0, to: 10 };
        let mut bundler = GraphBundler::default();
        bundler.sync(&nodes, &[edge]);
        assert!(!bundler.route(0, 10).is_empty());
        assert!(bundler.route(0, 11).is_empty());

        bundler.sync(&nodes, &[]);

        assert!(bundler.route(0, 10).is_empty());
        assert!(bundler.route(99, 0).is_empty());
    }

    #[test]
    fn a_blocked_attachment_detours_without_reentering_endpoint_cards() {
        let nodes = [
            RouteNode {
                id: 1,
                center: Point { x: 0.0, y: 0.0 },
                size: Size {
                    width: 100.0,
                    height: 60.0,
                },
            },
            RouteNode {
                id: 2,
                center: Point { x: 140.0, y: 0.0 },
                size: Size {
                    width: 100.0,
                    height: 60.0,
                },
            },
            RouteNode {
                id: 3,
                center: Point { x: -140.0, y: 0.0 },
                size: Size {
                    width: 100.0,
                    height: 60.0,
                },
            },
        ];
        let mut bundler = GraphBundler::default();
        bundler.sync(&nodes, &[LayoutEdge { from: 1, to: 2 }]);

        let route = bundler.route(1, 2);

        assert_clear(&route, &nodes);
    }

    #[test]
    fn incident_links_share_an_outer_attachment_without_losing_pair_identity() {
        let (nodes, _) = dense_cards(1, 16);
        let edges = [
            LayoutEdge { from: 0, to: 10 },
            LayoutEdge { from: 0, to: 11 },
        ];
        let mut bundler = GraphBundler::default();
        bundler.sync(&nodes, &edges);

        let first = bundler.route(0, 10);
        let second = bundler.route(0, 11);

        assert_eq!(
            &first[..2],
            &second[..2],
            "common source shares a geometric attachment"
        );
        assert_ne!(first.last(), second.last(), "destinations remain distinct");
        let (min, max) = bundler.bounds().unwrap();
        assert!(first.iter().any(|point| {
            (point.x - min.x).abs() < 0.001
                || (point.x - max.x).abs() < 0.001
                || (point.y - min.y).abs() < 0.001
                || (point.y - max.y).abs() < 0.001
        }));
        assert!(
            bundler.route(10, 11).is_empty(),
            "a shared lane cannot invent a neighbor relationship"
        );
    }
}
