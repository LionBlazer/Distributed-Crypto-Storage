//! Headless public renderer fixtures; no storage or query backend is executed.
use super::*;

struct CardFrame {
    bounds: egui::Rect,
    shapes: Vec<egui::epaint::ClippedShape>,
}

fn render_peer(scale: f32, name: &str) -> CardFrame {
    let context = egui::Context::default();
    set_theme(&context);
    let node = NetworkNode {
        id: 2,
        name: name.into(),
        role: NodeRole::Peer,
        peer_id: Some(1),
        online: true,
        process_id: None,
    };
    let state = LabSnapshot {
        name: "public renderer fixture".into(),
        revision: 0,
        owner_rows: vec![],
        peers: vec![fhe_playground::PeerInfo {
            id: 1,
            config: PeerConfig {
                storage_limit_bytes: 8192,
                ..PeerConfig::numbered(1)
            },
            online: true,
            rows: 4,
            logical_bytes: 12,
            data_bytes: 1024,
            index_bytes: 2048,
            stored_bytes: 4096,
            journal_bytes: 1024,
            public_setup_bytes: 0,
            owner_row_indices: vec![],
        }],
        replication: None,
    };
    let bounds = egui::Rect::from_min_size(egui::pos2(100.0, 100.0), NODE_SIZE * scale);
    let output = context.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 600.0),
            )),
            ..Default::default()
        },
        |ui| {
            draw_node(
                ui.painter(),
                bounds,
                &node,
                Some(&state),
                true,
                ui.visuals().widgets.inactive,
                scale,
            );
        },
    );
    let shapes = output.shapes.clone();
    output.drop_without_applying_deltas();
    CardFrame { bounds, shapes }
}

fn text_bounds(frame: &CardFrame) -> Vec<(String, egui::Rect)> {
    frame
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some((
                text.galley.job.text.clone(),
                text.galley.rect.translate(text.pos.to_vec2()),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn zoom_scales_every_label_with_its_card_without_changing_the_contents() {
    let full = render_peer(1.0, "Peer 01");
    let reference = text_bounds(&full);
    assert_eq!(reference.len(), 5);

    for scale in [0.08, 0.5, 0.71, 0.73, 2.5] {
        let frame = render_peer(scale, "Peer 01");
        let labels = text_bounds(&frame);
        assert_eq!(labels.len(), reference.len(), "zoom {scale}");
        for ((reference_text, reference_rect), (label, rect)) in reference.iter().zip(labels) {
            assert_eq!(*reference_text, label, "zoom {scale}");
            let expected = egui::emath::TSTransform::new(
                frame.bounds.min.to_vec2() - full.bounds.min.to_vec2() * scale,
                scale,
            ) * *reference_rect;
            assert!(
                rect.min.distance(expected.min) < 0.001 && rect.max.distance(expected.max) < 0.001,
                "zoom {scale}, {label}: expected {expected:?}, got {rect:?}"
            );
        }
    }
}

#[test]
fn storage_bar_status_dot_and_card_border_keep_the_same_world_dimensions() {
    for scale in [0.08, 0.5, 1.0, 2.5] {
        let frame = render_peer(scale, "Peer 01");
        let track = frame
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) if rect.fill == EDITOR => Some(rect.rect),
                _ => None,
            })
            .expect("storage track at every zoom");
        assert!((track.width() / scale - 200.0).abs() < 0.001);
        assert!((track.height() / scale - 5.0).abs() < 0.001);
        let fill = frame
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) if rect.fill == GREEN => Some(rect.rect),
                _ => None,
            })
            .expect("physical storage usage at every zoom");
        assert!((fill.width() / track.width() - 0.5).abs() < 0.001);
        let dot = frame
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Circle(dot) => Some(dot),
                _ => None,
            })
            .expect("status dot at every zoom");
        assert!((dot.radius / scale - 3.0).abs() < 0.001);
        let border = frame
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) if rect.stroke.width > 0.0 => Some(rect.stroke.width),
                _ => None,
            })
            .expect("card border at every zoom");
        assert!((border / scale - 1.0).abs() < 0.001);
    }
}

#[test]
fn far_zoom_clips_long_labels_inside_the_shrinking_card() {
    let scale = 0.04;
    let frame = render_peer(scale, &"Public long node label ".repeat(8));
    let labels = text_bounds(&frame);
    let title = &labels.iter().find(|(label, _)| label == "P01").unwrap().1;
    assert!(title.height() < 1.0, "no fixed pixel font minimum");
    let long_name = &labels
        .iter()
        .find(|(label, _)| label.starts_with("Public"))
        .unwrap()
        .1;
    assert!(long_name.width() > frame.bounds.width());
    for shape in &frame.shapes {
        if matches!(shape.shape, egui::Shape::Text(_) | egui::Shape::Circle(_)) {
            assert!(frame.bounds.contains_rect(shape.clip_rect));
            assert!(shape.clip_rect.width() < frame.bounds.width());
        }
    }
}
