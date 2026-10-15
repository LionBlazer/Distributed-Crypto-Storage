//! Opt-in, offline visual review of real egui meshes. No window or GPU is used.
use std::collections::HashMap;
use std::io::Write;

use super::*;

#[test]
#[ignore = "writes public-fixture UI previews to .local/gui-previews"]
fn export_ui_previews() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.local/gui-previews");
    std::fs::create_dir_all(&directory).unwrap();
    for (name, tab, peer_count, size) in [
        ("sql", Tab::Sql, 3, [1500, 900]),
        ("sql-narrow", Tab::Sql, 3, [1180, 720]),
        ("selected-result", Tab::Sql, 3, [1500, 900]),
        ("selected-narrow", Tab::Sql, 3, [1180, 720]),
        ("navigation-peer", Tab::Sql, 3, [1500, 900]),
        ("navigation-back", Tab::Sql, 3, [1500, 900]),
        ("data", Tab::Data, 3, [1500, 900]),
        ("network", Tab::Sql, 8, [1500, 900]),
        ("network-small", Tab::Sql, 16, [1180, 720]),
        ("network-map", Tab::Sql, 16, [1500, 900]),
        ("network-max", Tab::Sql, 16, [1500, 900]),
        ("peer-tab", Tab::Sql, 3, [1500, 900]),
    ] {
        let (mut app, _commands, _events) = app();
        app.snapshot = Some(snapshot(peer_count));
        app.network = Some(network(
            peer_count,
            if name == "network-max" { 8 } else { 1 },
        ));
        if name == "network-map" {
            app.network_view = NetworkView::Map;
        }
        for peer in &mut app.snapshot.as_mut().unwrap().peers {
            peer.data_bytes = 112 + peer.rows * 3 + if peer.rows == 0 { 0 } else { 48 };
            peer.index_bytes = 2328 + peer.rows * 4;
            peer.stored_bytes = peer.data_bytes + peer.index_bytes;
        }
        app.tab = tab;
        if name == "peer-tab" {
            app.open_node(3);
        }
        if name.starts_with("selected-") {
            // Public renderer fixture only: no query is executed or backend
            // result claimed by this opt-in, window-free preview.
            app.sql = "SELECT age, amount\nFROM records\nWHERE age >= 18\nLIMIT 10;".into();
            app.status = "Public result fixture / no backend execution".into();
            app.history.push_front(Record {
                job: Job::Query,
                label: app.sql.clone(),
                database: "demo".into(),
                revision: 0,
                elapsed_ms: 0.0,
                outcome: Ok(Outcome::Query(QueryOutcome::Selected {
                    columns: vec![Column::Age, Column::Amount],
                    rows: vec![vec![18, 20], vec![42, 30]],
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
        for frame in 0..3 {
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(size[0] as f32, size[1] as f32),
                    )),
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
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
            if frame == 2 {
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
