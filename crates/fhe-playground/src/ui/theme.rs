use eframe::egui::{self, Color32, FontId, RichText, Stroke};

pub(super) const EDITOR: Color32 = Color32::from_rgb(17, 20, 27);
pub(super) const PANEL: Color32 = Color32::from_rgb(24, 28, 37);
pub(super) const CARD: Color32 = Color32::from_rgb(30, 35, 46);
pub(super) const BORDER: Color32 = Color32::from_rgb(47, 55, 70);
pub(super) const TEXT: Color32 = Color32::from_rgb(222, 230, 242);
pub(super) const MUTED: Color32 = Color32::from_rgb(135, 149, 171);
pub(super) const ACCENT: Color32 = Color32::from_rgb(105, 180, 255);
pub(super) const GREEN: Color32 = Color32::from_rgb(108, 206, 166);
pub(super) const AMBER: Color32 = Color32::from_rgb(236, 185, 107);
pub(super) const RED: Color32 = Color32::from_rgb(239, 126, 142);

#[derive(Clone, Copy)]
pub(super) enum Icon {
    Database,
    Table,
}

pub(super) fn icon(ui: &mut egui::Ui, kind: Icon, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
    let p = ui.painter();
    let r = rect.shrink(3.0);
    let s = Stroke::new(1.3, color);
    match kind {
        Icon::Database => {
            p.rect_stroke(r, 3, s, egui::StrokeKind::Inside);
            for offset in [4.0, 8.0] {
                p.line_segment(
                    [
                        r.left_top() + egui::vec2(0.0, offset),
                        r.right_top() + egui::vec2(0.0, offset),
                    ],
                    s,
                );
            }
        }
        Icon::Table => {
            p.rect_stroke(r, 2, s, egui::StrokeKind::Inside);
            p.line_segment([r.left_center(), r.right_center()], s);
            p.line_segment([r.center_top(), r.center_bottom()], s);
        }
    }
}

pub(super) fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).color(color));
        });
}

pub(super) fn section(ui: &mut egui::Ui, label: &str) {
    ui.add_space(12.0);
    ui.label(RichText::new(label).size(12.0).strong().color(MUTED));
    ui.add_space(5.0);
}

#[derive(Clone, Copy)]
enum ControlKind {
    Primary,
    Neutral,
    Tab { selected: bool },
}

pub(super) struct ActionButton<'a> {
    label: &'a str,
    kind: ControlKind,
}

impl egui::Widget for ActionButton<'_> {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        // Reserve the background before the real Button paints its label. Keeping
        // the Button preserves keyboard activation, focus and accessibility; its
        // current response determines the colors rather than guessed pointer bounds.
        let background = ui.painter().add(egui::Shape::Noop);
        let primary = matches!(self.kind, ControlKind::Primary);
        let text = RichText::new(self.label).color(if primary && ui.is_enabled() {
            EDITOR
        } else {
            TEXT
        });
        let text = if primary { text.strong() } else { text };
        let response = ui.add(
            egui::Button::new(text)
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::NONE)
                .min_size(egui::vec2(0.0, 30.0)),
        );
        let selected = matches!(self.kind, ControlKind::Tab { selected: true });
        let mut visuals = control_visuals(ui, &response, selected);
        if primary && response.enabled() {
            visuals.weak_bg_fill = if response.is_pointer_button_down_on() {
                Color32::from_rgb(63, 140, 221)
            } else if response.hovered() {
                Color32::from_rgb(146, 203, 255)
            } else {
                ACCENT
            };
            visuals.bg_stroke = Stroke::new(1.0, visuals.weak_bg_fill);
            if response.has_focus() {
                visuals.bg_stroke = Stroke::new(2.0, Color32::WHITE);
            }
        }
        ui.painter().set(
            background,
            egui::epaint::RectShape::new(
                response.rect,
                5,
                visuals.weak_bg_fill,
                visuals.bg_stroke,
                egui::StrokeKind::Inside,
            ),
        );
        if response.enabled() {
            response.on_hover_cursor(egui::CursorIcon::PointingHand)
        } else {
            response
        }
    }
}

pub(super) fn primary(label: &str) -> ActionButton<'_> {
    ActionButton {
        label,
        kind: ControlKind::Primary,
    }
}

pub(super) fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(enabled, primary(label))
}

pub(super) fn action_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        ActionButton {
            label,
            kind: ControlKind::Neutral,
        },
    )
}

pub(super) fn tab_button(ui: &mut egui::Ui, label: &str, selected: bool) -> egui::Response {
    ui.add(ActionButton {
        label,
        kind: ControlKind::Tab { selected },
    })
}

/// Shared response-based feedback for painted graph nodes and button backgrounds.
pub(super) fn control_visuals(
    ui: &egui::Ui,
    response: &egui::Response,
    selected: bool,
) -> egui::style::WidgetVisuals {
    let widgets = &ui.visuals().widgets;
    let mut visuals = if !response.enabled() {
        widgets.noninteractive
    } else if response.is_pointer_button_down_on() {
        widgets.active
    } else if response.hovered() {
        widgets.hovered
    } else {
        widgets.inactive
    };
    if selected && response.enabled() {
        visuals.weak_bg_fill = if response.is_pointer_button_down_on() {
            Color32::from_rgb(51, 101, 151)
        } else if response.hovered() {
            Color32::from_rgb(43, 77, 111)
        } else {
            Color32::from_rgb(33, 55, 79)
        };
        visuals.bg_fill = visuals.weak_bg_fill;
        visuals.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.65));
    }
    if response.has_focus() && response.enabled() {
        visuals.bg_stroke = Stroke::new(2.0, ACCENT);
    }
    visuals
}

pub(super) fn bytes(value: usize) -> String {
    if value >= 1024 * 1024 {
        format!("{:.1} MiB", value as f64 / (1024.0 * 1024.0))
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}

pub(super) fn set_theme(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.panel_fill = PANEL;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = EDITOR;
    style.visuals.faint_bg_color = CARD;
    style.visuals.selection.bg_fill = Color32::from_rgb(36, 66, 97);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.interact_cursor = Some(egui::CursorIcon::PointingHand);
    style.visuals.disabled_alpha = 0.5;
    style.visuals.widgets.noninteractive.weak_bg_fill = EDITOR;
    style.visuals.widgets.noninteractive.bg_fill = EDITOR;
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    style.visuals.widgets.inactive.weak_bg_fill = CARD;
    style.visuals.widgets.inactive.bg_fill = CARD;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(43, 54, 72);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(43, 54, 72);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.6));
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(37, 67, 98);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(37, 67, 98);
    style.visuals.widgets.active.bg_stroke = Stroke::new(2.0, ACCENT);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.open = style.visuals.widgets.active;
    for visuals in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        visuals.corner_radius = 5.into();
        visuals.expansion = 0.0;
    }
    style.spacing.item_spacing = egui::vec2(9.0, 7.0);
    style.spacing.button_padding = egui::vec2(11.0, 6.0);
    style.spacing.interact_size.y = 28.0;
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, FontId::monospace(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, FontId::proportional(20.0));
    ctx.set_global_style(style);
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod control_tests;
