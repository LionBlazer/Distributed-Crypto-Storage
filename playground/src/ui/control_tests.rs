use super::*;

#[derive(Clone, Copy)]
enum Control {
    SqlRun,
    SqlStop,
    Primary,
    Neutral,
    SelectedTab,
    NativeButton,
    Number,
    Text,
}

struct Frame {
    response: egui::Response,
    background: Color32,
    border: Stroke,
    cursor: egui::CursorIcon,
}

// Only egui input and output are used. These examples never create a window or
// send OS input, and check the shapes presented to the user rather than palettes.
fn draw(ctx: &egui::Context, control: Control, enabled: bool, events: Vec<egui::Event>) -> Frame {
    let mut response = None;
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(500.0, 160.0),
            )),
            events,
            ..Default::default()
        },
        |ui| {
            response = Some(
                ui.add_enabled_ui(enabled, |ui| match control {
                    Control::SqlRun => run_button(ui, true),
                    Control::SqlStop => stop_button(ui, true),
                    Control::Primary => primary_button(ui, "Run", true),
                    Control::Neutral => action_button(ui, "Apply", true),
                    Control::SelectedTab => view_tab(ui, "SQL", true, false).response,
                    Control::NativeButton => ui.button("Generate"),
                    Control::Number => ui.add(egui::DragValue::new(&mut 3)),
                    Control::Text => ui.text_edit_singleline(&mut "demo".to_string()),
                })
                .inner,
            );
        },
    );
    let response = response.unwrap();
    let painted = output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Rect(rect)
                if rect.rect.contains(response.rect.center())
                    && rect.rect.width() >= response.rect.width() - 4.0
                    && rect.rect.width() <= response.rect.width() + 4.0
                    && rect.fill != Color32::TRANSPARENT =>
            {
                Some(rect)
            }
            _ => None,
        })
        .next_back()
        .expect("the control paints a background");
    Frame {
        response,
        background: painted.fill,
        border: painted.stroke,
        cursor: output.platform_output.cursor_icon,
    }
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    set_theme(&ctx);
    ctx
}

fn pointer_button(position: egui::Pos2, pressed: bool) -> egui::Event {
    egui::Event::PointerButton {
        pos: position,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    }
}

#[test]
fn buttons_and_tabs_show_distinct_hover_and_held_colors() {
    for control in [
        Control::SqlRun,
        Control::SqlStop,
        Control::Primary,
        Control::Neutral,
        Control::SelectedTab,
        Control::NativeButton,
        Control::Number,
    ] {
        let ctx = context();
        let idle = draw(&ctx, control, true, vec![]);
        let center = idle.response.rect.center();
        let hovered = draw(&ctx, control, true, vec![egui::Event::PointerMoved(center)]);
        let held = draw(&ctx, control, true, vec![pointer_button(center, true)]);

        assert!(hovered.response.hovered());
        assert!(held.response.is_pointer_button_down_on());
        assert_ne!(
            idle.background, hovered.background,
            "hover changes the fill"
        );
        assert_ne!(
            hovered.background, held.background,
            "holding changes the fill again"
        );
        assert_eq!(
            hovered.cursor,
            if matches!(control, Control::Number) {
                egui::CursorIcon::ResizeHorizontal
            } else {
                egui::CursorIcon::PointingHand
            },
        );
    }
}

#[test]
fn disabled_actions_are_dimmed_and_never_dispatch_a_click() {
    for control in [Control::Primary, Control::Neutral, Control::SelectedTab] {
        let ctx = context();
        let active = draw(&ctx, control, true, vec![]);
        let disabled = draw(&ctx, control, false, vec![]);
        let center = disabled.response.rect.center();
        draw(
            &ctx,
            control,
            false,
            vec![egui::Event::PointerMoved(center)],
        );
        draw(&ctx, control, false, vec![pointer_button(center, true)]);
        let released = draw(&ctx, control, false, vec![pointer_button(center, false)]);

        assert!(!released.response.enabled());
        assert!(!released.response.clicked());
        assert_ne!(active.background, disabled.background);
        assert_ne!(released.cursor, egui::CursorIcon::PointingHand);
    }
}

#[test]
fn focused_primary_action_keeps_focus_outline_and_keyboard_activation() {
    let ctx = context();
    let idle = draw(&ctx, Control::Primary, true, vec![]);
    ctx.memory_mut(|memory| memory.request_focus(idle.response.id));

    let focused = draw(&ctx, Control::Primary, true, vec![egui::Event::PointerGone]);
    assert!(focused.response.has_focus());
    assert_eq!(focused.background, idle.background);
    assert!(focused.border.width > idle.border.width);
    assert_ne!(focused.border.color, idle.border.color);

    let activated = draw(
        &ctx,
        Control::Primary,
        true,
        vec![egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }],
    );
    assert!(activated.response.clicked());
}

#[test]
fn text_input_highlights_its_border_and_retains_an_edit_cursor() {
    let ctx = context();
    let idle = draw(&ctx, Control::Text, true, vec![]);
    let center = idle.response.rect.center();
    let hovered = draw(
        &ctx,
        Control::Text,
        true,
        vec![egui::Event::PointerMoved(center)],
    );
    let held = draw(
        &ctx,
        Control::Text,
        true,
        vec![pointer_button(center, true)],
    );

    assert_ne!(idle.border.color, hovered.border.color);
    assert_ne!(hovered.border, held.border);
    assert_eq!(hovered.cursor, egui::CursorIcon::Text);
    assert!(held.response.has_focus());
}
