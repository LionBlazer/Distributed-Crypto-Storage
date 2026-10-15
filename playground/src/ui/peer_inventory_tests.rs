//! Public manager view fixtures, independent of a database and encrypted storage.
use super::*;
use crate::process_backend::PeerProfile;
use infrastructure::GraphAction;
use std::sync::mpsc::{Receiver, TryRecvError};

fn pre_database() -> (Playground, Receiver<Command>) {
    let (worker, commands, _events) = Worker::test_channel();
    let mut app = Playground::with_worker(worker);
    let profiles: Vec<_> = (1..=2)
        .map(|id| PeerProfile {
            node: id as NodeId + 1,
            id,
            config: crate::process_backend::default_peer_config(id),
        })
        .collect();
    let nodes = profiles
        .iter()
        .map(|peer| fhe_playground::NetworkNode {
            id: peer.node,
            name: peer.config.name.clone(),
            role: NodeRole::Peer,
            peer_id: Some(peer.id),
            online: true,
            process_id: None,
        })
        .collect();
    app.apply_display_event(Event::Peers(profiles));
    app.apply_display_event(Event::Network(NetworkSnapshot {
        time_ms: 0.0,
        speed: 1.0,
        paused: false,
        nodes,
        links: vec![],
        packets: vec![],
        recent: vec![],
    }));
    (app, commands)
}

fn render(
    context: &egui::Context,
    app: &mut Playground,
    events: Vec<egui::Event>,
) -> Vec<(String, egui::Rect)> {
    let output = context.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1500.0, 900.0),
            )),
            events,
            ..Default::default()
        },
        |ui| app.draw(ui),
    );
    fn collect(shape: &egui::Shape, texts: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(shape) => texts.push((
                shape.galley.job.text.clone(),
                shape.galley.rect.translate(shape.pos.to_vec2()),
            )),
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, texts);
                }
            }
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut texts);
    }
    output.drop_without_applying_deltas();
    texts
}

#[test]
fn new_peer_names_and_database_creation_use_existing_process_profiles_before_a_database_exists() {
    let (mut app, commands) = pre_database();
    assert!(app.snapshot.is_none());
    app.peer_inventory[0].config.name = "Custom pre-database peer".into();
    let profiles = app.profiles();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0].name, "Custom pre-database peer");
    assert_eq!(profiles[1].name, "Peer 02");

    app.graph_action(
        GraphAction::AddPeer(egui::Pos2::ZERO),
        egui::Rect::EVERYTHING,
    );

    assert!(
        matches!(commands.try_recv(), Ok(Command::AddPeer(config)) if config.name == "Peer 03")
    );
}

#[test]
fn peer_settings_before_database_creation_submit_actual_peer_id_without_fabricating_storage() {
    let (mut app, commands) = pre_database();
    app.open_node(3);
    let expected = PeerConfig {
        name: "Configured peer".into(),
        storage_limit_bytes: 32 * 1024 * 1024,
        ..app.peer_edits[&3].clone()
    };
    app.peer_edits.insert(3, expected.clone());
    let context = egui::Context::default();
    set_theme(&context);
    let texts = render(&context, &mut app, vec![]);
    assert!(texts.iter().any(|(text, _)| text == "Storage quota"));
    assert!(!texts.iter().any(|(text, _)| text == "Encrypted shard"));
    let save = texts
        .iter()
        .find(|(text, _)| text == "Save settings")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        render(
            &context,
            &mut app,
            vec![
                egui::Event::PointerMoved(save),
                egui::Event::PointerButton {
                    pos: save,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    match commands.try_recv() {
        Ok(Command::ConfigurePeer { id, config }) => {
            assert_eq!(id, 2);
            assert_eq!(config, expected);
        }
        _ => panic!("Save settings did not submit peer configuration"),
    }
    assert!(app.snapshot.is_none());
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
