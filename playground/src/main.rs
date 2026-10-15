mod graph_bundling;
mod graph_layout;
mod graph_routing;
mod ui;
mod worker;

fn main() -> eframe::Result {
    if cfg!(debug_assertions) {
        eprintln!("Run the FHE GUI with: cargo run --release --locked -p fhe-playground");
        std::process::exit(1);
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()
        .expect("configure the GUI's eight FHE CPU threads");
    eframe::run_native(
        "DCS | FHE Playground",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1500.0, 900.0])
                .with_min_inner_size([1180.0, 720.0]),
            renderer: eframe::Renderer::Glow,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(ui::Playground::new(&cc.egui_ctx)?))),
    )
}
