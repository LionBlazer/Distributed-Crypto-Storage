//! Opt-in, offline visual review of real egui meshes. No window or GPU is used.
use std::collections::HashMap;
use std::io::Write;

use super::*;

#[test]
#[ignore = "writes public-fixture UI previews to .local/gui-previews"]
fn export_ui_previews() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.local/gui-previews");
    std::fs::create_dir_all(&directory).unwrap();
    for (name, tab, peer_count, size) in [
        ("sql", Tab::Sql, 3, [1500, 900]),
        ("sql-narrow", Tab::Sql, 3, [1180, 720]),
        ("presets", Tab::Sql, 3, [1500, 900]),
        ("presets-narrow", Tab::Sql, 3, [1180, 720]),
        ("selected-result", Tab::Sql, 3, [1500, 900]),
        ("selected-narrow", Tab::Sql, 3, [1180, 720]),
        ("selected-scroll", Tab::Sql, 3, [1500, 900]),
        ("settings", Tab::Sql, 3, [1500, 900]),
        ("navigation-peer", Tab::Sql, 3, [1500, 900]),
        ("navigation-back", Tab::Sql, 3, [1500, 900]),
        ("tabs-aligned", Tab::Sql, 3, [1500, 900]),
        ("tabs-narrow", Tab::Sql, 16, [1180, 720]),
        ("data", Tab::Data, 3, [1500, 900]),
        ("typed-catalog", Tab::Data, 3, [1500, 900]),
        ("typed-sql", Tab::Sql, 3, [1500, 900]),
        ("empty-workspace", Tab::Data, 3, [1500, 900]),
        ("empty-sql", Tab::Sql, 3, [1500, 900]),
        ("sql-running", Tab::Sql, 3, [1500, 900]),
        ("network", Tab::Sql, 8, [1500, 900]),
        ("network-small", Tab::Sql, 16, [1180, 720]),
        ("network-map", Tab::Sql, 16, [1500, 900]),
        ("network-overview", Tab::Sql, 16, [1500, 900]),
        ("network-traffic", Tab::Sql, 3, [1500, 900]),
        ("peer-storage", Tab::Sql, 3, [1500, 900]),
        ("peer-storage-narrow", Tab::Sql, 3, [1180, 720]),
        ("network-max", Tab::Sql, 16, [1500, 900]),
        ("peer-tab", Tab::Sql, 3, [1500, 900]),
    ] {
        let (mut app, _commands, _events) = app();
        app.snapshot = Some(snapshot(peer_count));
        app.status = "Public renderer fixture / no backend execution".into();
        app.network = Some(network(
            peer_count,
            if name == "network-max" { 8 } else { 1 },
        ));
        if name == "empty-workspace" || name == "empty-sql" {
            app.snapshot = None;
            app.network = Some(network(0, 1));
            app.draft_rows.clear();
            app.draft_name = "database".into();
        }
        if name == "sql-running" {
            app.run_query();
            app.status = "Public pending-operation renderer fixture / no backend execution".into();
        }
        if name.starts_with("typed-") {
            // Public owner schema metadata fixture only. No peer response or
            // computation proof is fabricated for visual review.
            let fixture = relational_types::import_database_dump(
                "CREATE TABLE Customers (CustomerID NCHAR(5) NOT NULL, CompanyName NVARCHAR(80) NOT NULL, City NVARCHAR(40) NULL); CREATE TABLE Orders (OrderID INT NOT NULL, CustomerID NCHAR(5) NULL, Freight MONEY NULL); CREATE TABLE [Order Details] (OrderID INT NOT NULL, ProductID INT NOT NULL, UnitPrice MONEY NULL);",
                relational_types::ImportLimits::default(),
            ).unwrap();
            app.catalog = fixture
                .tables
                .into_iter()
                .map(|table| (table.schema, table.rows.len()))
                .collect();
            app.select_catalog_table(0);
            if let Some(state) = &mut app.snapshot {
                state.name = "Public typed schema fixture".into();
                state.owner_rows.clear();
            }
        }
        if name == "network-map" {
            app.network_view = NetworkView::Map;
        }
        if name == "network-overview" {
            app.network = Some(large_observed_topology());
            app.snapshot = None;
            app.active_client = None;
        }
        if name == "network-traffic" {
            for (id, from, to, kind) in [
                (90001, 1, 2, fhe_playground::PacketKind::Request),
                (90002, 3, 1, fhe_playground::PacketKind::Response),
            ] {
                app.playback.observe(&fhe_playground::NetworkPacket {
                    id,
                    from,
                    to,
                    kind,
                    progress: 1.0,
                    request_id: Some(9),
                });
            }
        }
        if name.starts_with("peer-storage") {
            // Public synthetic input, real encrypted-storage accounting. The
            // renderer consumes this engine snapshot without estimated sizes.
            let mut engine = fhe_playground::LabEngine::default();
            let peers = (1..=3)
                .map(|id| PeerConfig {
                    storage_limit_bytes: 8192,
                    ..PeerConfig::numbered(id)
                })
                .collect();
            app.snapshot = Some(
                engine
                    .create(DatabaseDraft {
                        name: "storage-demo".into(),
                        rows: sample_rows(4).unwrap(),
                        peers,
                    })
                    .unwrap(),
            );
            app.network_view = NetworkView::Map;
            app.status = "Public fixture / actual encrypted storage sizes".into();
        }
        app.tab = tab;
        if name == "settings" {
            app.navigate(tab, RightTab::Settings);
        }
        if name == "tabs-narrow" {
            for id in 2..=17 {
                app.open_node(id);
            }
        }
        if name == "tabs-aligned" {
            for id in 2..=4 {
                app.open_node(id);
            }
            app.navigate(tab, RightTab::Network);
        }
        if name == "peer-tab" {
            app.open_node(3);
        }
        if name.starts_with("selected-") {
            // Public renderer fixture only: no query is executed or backend
            // result claimed by this opt-in, window-free preview.
            app.sql = if name == "selected-scroll" {
                "SELECT age, amount\nFROM records;"
            } else {
                "SELECT age, amount\nFROM records\nWHERE age >= 18\nLIMIT 10;"
            }
            .into();
            app.status = "Public result fixture / no backend execution".into();
            app.history.push_front(Record {
                job: Job::Query,
                label: app.sql.clone(),
                database: "demo".into(),
                revision: 0,
                elapsed_ms: 0.0,
                outcome: Ok(Outcome::Query(QueryOutcome::Selected {
                    columns: vec![Column::Age, Column::Amount],
                    rows: if name == "selected-scroll" {
                        (0..128).map(|age| vec![age, age]).collect()
                    } else {
                        vec![vec![18, 20], vec![42, 30]]
                    },
                })),
            });
        }
        if name.starts_with("navigation-") {
            app.open_node(2);
            app.open_node(3);
            if name == "navigation-back" {
                app.navigate_history(false);
            }
        }
        let ctx = egui::Context::default();
        set_theme(&ctx);
        let mut textures = HashMap::new();
        let show_presets = name.starts_with("presets");
        let frame_count = if show_presets || name == "tabs-narrow" || name == "selected-scroll" {
            12
        } else {
            3
        };
        let mut preset_position = None;
        for frame in 0..frame_count {
            // Exercise the actual menu in the in-memory egui context. This
            // generates no OS input and never dispatches a SQL command.
            let events = if show_presets && (frame == 1 || frame == 2) {
                let position = preset_position.expect("Presets button is visible");
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed: frame == 1,
                        modifiers: egui::Modifiers::NONE,
                    },
                ]
            } else if name == "selected-scroll" {
                vec![egui::Event::PointerMoved(egui::pos2(603.0, 700.0))]
            } else {
                Vec::new()
            };
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(size[0] as f32, size[1] as f32),
                    )),
                    // Advance egui's clock explicitly, including enough time
                    // after opening the popup for its normal fade to finish.
                    time: Some(frame as f64 * 0.1),
                    predicted_dt: 0.1,
                    events,
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            if show_presets && frame == 0 {
                preset_position = output
                    .shapes
                    .iter()
                    .find_map(|shape| text_center(&shape.shape, "Presets"));
            }
            for (id, deltas) in &output.textures_delta.set {
                for delta in deltas {
                    let egui::ImageData::Color(image) = &delta.image;
                    if let Some([x, y]) = delta.pos {
                        let texture: &mut egui::ColorImage = textures.get_mut(id).unwrap();
                        for row in 0..image.size[1] {
                            let start = (y + row) * texture.size[0] + x;
                            texture.pixels[start..start + image.size[0]].copy_from_slice(
                                &image.pixels[row * image.size[0]..(row + 1) * image.size[0]],
                            );
                        }
                    } else {
                        textures.insert(*id, (**image).clone());
                    }
                }
            }
            if frame + 1 == frame_count {
                let meshes = ctx.tessellate(output.shapes.clone(), output.pixels_per_point);
                let pixels = rasterize(meshes, &textures, size);
                let path = directory.join(format!("{name}.ppm"));
                let mut file = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
                write!(file, "P6\n{} {}\n255\n", size[0], size[1]).unwrap();
                file.write_all(&pixels).unwrap();
                println!("{}", path.display());
            }
            output.drop_without_applying_deltas();
        }
    }
}

fn text_center(shape: &egui::Shape, label: &str) -> Option<egui::Pos2> {
    match shape {
        egui::Shape::Text(text) if text.galley.job.text == label => {
            Some(text.galley.rect.translate(text.pos.to_vec2()).center())
        }
        egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| text_center(shape, label)),
        _ => None,
    }
}

fn rasterize(
    meshes: Vec<egui::ClippedPrimitive>,
    textures: &HashMap<egui::TextureId, egui::ColorImage>,
    size: [usize; 2],
) -> Vec<u8> {
    let mut pixels = vec![0; size[0] * size[1] * 3];
    for primitive in meshes {
        let egui::epaint::Primitive::Mesh(mesh) = primitive.primitive else {
            continue;
        };
        let texture = &textures[&mesh.texture_id];
        for triangle in mesh.indices.as_chunks::<3>().0 {
            let v = [
                mesh.vertices[triangle[0] as usize],
                mesh.vertices[triangle[1] as usize],
                mesh.vertices[triangle[2] as usize],
            ];
            let area = cross(v[1].pos - v[0].pos, v[2].pos - v[0].pos);
            if area.abs() < 0.0001 {
                continue;
            }
            let bounds = egui::Rect::from_points(&[v[0].pos, v[1].pos, v[2].pos])
                .intersect(primitive.clip_rect);
            let min_x = bounds.left().floor().max(0.0) as usize;
            let max_x = (bounds.right().ceil().max(0.0) as usize).min(size[0]);
            let min_y = bounds.top().floor().max(0.0) as usize;
            let max_y = (bounds.bottom().ceil().max(0.0) as usize).min(size[1]);
            for y in min_y..max_y {
                for x in min_x..max_x {
                    let point = egui::pos2(x as f32 + 0.5, y as f32 + 0.5);
                    let a = cross(v[1].pos - point, v[2].pos - point) / area;
                    let b = cross(v[2].pos - point, v[0].pos - point) / area;
                    let c = 1.0 - a - b;
                    if a < 0.0 || b < 0.0 || c < 0.0 {
                        continue;
                    }
                    let uv = v[0].uv.to_vec2() * a + v[1].uv.to_vec2() * b + v[2].uv.to_vec2() * c;
                    let sample = sample_texture(texture, uv);
                    let mut color = [0.0; 4];
                    for (component, value) in color.iter_mut().enumerate() {
                        *value = (v[0].color.to_array()[component] as f32 * a
                            + v[1].color.to_array()[component] as f32 * b
                            + v[2].color.to_array()[component] as f32 * c)
                            * sample[component]
                            / 255.0;
                    }
                    let index = (y * size[0] + x) * 3;
                    for channel in 0..3 {
                        pixels[index + channel] = (color[channel]
                            + pixels[index + channel] as f32 * (1.0 - color[3] / 255.0))
                            .clamp(0.0, 255.0)
                            as u8;
                    }
                }
            }
        }
    }
    pixels
}

fn cross(a: egui::Vec2, b: egui::Vec2) -> f32 {
    a.x * b.y - a.y * b.x
}

fn sample_texture(image: &egui::ColorImage, uv: egui::Vec2) -> [f32; 4] {
    let pos = uv * egui::vec2(image.size[0] as f32, image.size[1] as f32) - egui::vec2(0.5, 0.5);
    let x = pos.x.floor();
    let y = pos.y.floor();
    let mut sample = [0.0; 4];
    for dy in 0..2 {
        for dx in 0..2 {
            let ix = ((x + dx as f32).max(0.0) as usize).min(image.size[0] - 1);
            let iy = ((y + dy as f32).max(0.0) as usize).min(image.size[1] - 1);
            let weight = if dx == 0 {
                1.0 - (pos.x - x)
            } else {
                pos.x - x
            } * if dy == 0 {
                1.0 - (pos.y - y)
            } else {
                pos.y - y
            };
            for (component, value) in sample.iter_mut().enumerate() {
                *value +=
                    image.pixels[iy * image.size[0] + ix].to_array()[component] as f32 * weight;
            }
        }
    }
    sample
}
