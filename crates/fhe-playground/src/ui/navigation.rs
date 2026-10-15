//! Bounded presentation history. Navigation never submits a worker command.
use super::{Playground, RightTab, Tab};
use eframe::egui;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    pub left: Tab,
    pub right: RightTab,
}

pub(super) struct Navigation {
    entries: Vec<Route>,
    cursor: usize,
}

const CAPACITY: usize = 256;

impl Default for Navigation {
    fn default() -> Self {
        Self {
            entries: vec![Route {
                left: Tab::Sql,
                right: RightTab::Network,
            }],
            cursor: 0,
        }
    }
}

impl Navigation {
    pub fn visit(&mut self, route: Route) {
        if self.entries[self.cursor] == route {
            return;
        }
        self.entries.truncate(self.cursor + 1);
        self.entries.push(route);
        self.cursor = self.entries.len() - 1;
        self.bound();
    }

    pub fn can_step(&self, forward: bool) -> bool {
        if forward {
            self.cursor + 1 < self.entries.len()
        } else {
            self.cursor > 0
        }
    }

    pub fn step(&mut self, forward: bool) -> Option<Route> {
        if !self.can_step(forward) {
            return None;
        }
        if forward {
            self.cursor += 1;
        } else {
            self.cursor -= 1;
        }
        Some(self.entries[self.cursor])
    }

    pub fn retain(&mut self, valid: impl Fn(Route) -> bool, fallback: Route) -> Route {
        let current = self.entries[self.cursor];
        let before = self.entries[..self.cursor]
            .iter()
            .filter(|route| valid(**route))
            .count();
        self.entries.retain(|route| valid(*route));
        if valid(current) {
            self.cursor = before;
        } else if before > 0 && self.entries[before - 1] == fallback {
            self.cursor = before - 1;
        } else if self.entries.get(before) == Some(&fallback) {
            self.cursor = before;
        } else {
            self.entries.insert(before, fallback);
            self.cursor = before;
        }
        // Insert the current fallback before deduplication: it can separate two
        // equal Network routes that still have distinct backward/forward intent.
        let mut distinct = Vec::with_capacity(self.entries.len());
        let mut cursor = 0;
        for (index, route) in self.entries.iter().copied().enumerate() {
            if distinct.last() != Some(&route) {
                distinct.push(route);
            }
            if index == self.cursor {
                cursor = distinct.len() - 1;
            }
        }
        self.entries = distinct;
        self.cursor = cursor;
        self.bound();
        self.entries[self.cursor]
    }

    fn bound(&mut self) {
        while self.entries.len() > CAPACITY {
            if self.cursor > 0 {
                self.entries.remove(0);
                self.cursor -= 1;
            } else {
                self.entries.pop();
            }
        }
    }
}

impl Playground {
    pub(super) fn navigate(&mut self, left: Tab, right: RightTab) {
        let route = Route { left, right };
        self.navigation.visit(route);
        self.restore_route(route);
    }

    fn restore_route(&mut self, route: Route) {
        self.tab = route.left;
        self.right_tab = route.right;
        if let RightTab::Node(id) = route.right {
            self.selected_node = Some(id);
        }
    }

    pub(super) fn navigate_history(&mut self, forward: bool) {
        self.prune_navigation();
        if let Some(route) = self.navigation.step(forward) {
            self.restore_route(route);
        }
    }

    pub(super) fn close_node_tab(&mut self, id: u64) {
        let Some(index) = self.node_tabs.iter().position(|node| *node == id) else {
            return;
        };
        let fallback = if self.right_tab == RightTab::Node(id) {
            self.node_tabs
                .get(index + 1)
                .or_else(|| {
                    index
                        .checked_sub(1)
                        .and_then(|previous| self.node_tabs.get(previous))
                })
                .copied()
                .map_or(RightTab::Network, RightTab::Node)
        } else {
            RightTab::Network
        };
        self.node_tabs.retain(|node| *node != id);
        self.prune_navigation_with_fallback(fallback);
    }

    pub(super) fn prune_navigation(&mut self) {
        self.prune_navigation_with_fallback(RightTab::Network);
    }

    fn prune_navigation_with_fallback(&mut self, right: RightTab) {
        let fallback = Route {
            left: self.tab,
            right,
        };
        let tabs = &self.node_tabs;
        let network = self.network.as_ref();
        let route = self.navigation.retain(
            |route| match route.right {
                RightTab::Network | RightTab::Settings => true,
                RightTab::Node(id) => {
                    tabs.contains(&id)
                        && network.is_some_and(|net| net.nodes.iter().any(|node| node.id == id))
                }
            },
            fallback,
        );
        self.restore_route(route);
    }

    pub(super) fn navigation_shortcuts(&mut self, ctx: &egui::Context) {
        let (back, forward) = ctx.input_mut(|input| {
            let first_key_press = |key| {
                input.events.iter().any(|event| matches!(event,
                egui::Event::Key { key: pressed_key, pressed: true, repeat: false, modifiers, .. }
                    if *pressed_key == key && *modifiers == egui::Modifiers::ALT
            ))
            };
            let back = first_key_press(egui::Key::ArrowLeft)
                || input.pointer.button_pressed(egui::PointerButton::Extra1);
            let forward = first_key_press(egui::Key::ArrowRight)
                || input.pointer.button_pressed(egui::PointerButton::Extra2);
            input.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft);
            input.consume_key(egui::Modifiers::ALT, egui::Key::ArrowRight);
            (back, forward)
        });
        if back || forward {
            egui::Popup::close_all(ctx);
            self.navigate_history(!back);
        }
    }
}
