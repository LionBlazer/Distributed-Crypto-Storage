mod graph_bundling;
mod graph_layout;
mod graph_routing;
mod process_backend;
mod ui;
mod worker;

fn main() -> eframe::Result {
    if cfg!(debug_assertions) {
        eprintln!("Run the FHE GUI with: cargo run --release --locked -p dcs-launch -- playground");
        std::process::exit(1);
    }
    let kernel_directory = std::env::current_exe()
        .expect("resolve the GUI executable")
        .parent()
        .expect("the GUI executable has a parent directory")
        .join("proof-kernels");
    match bfv_query_proof::initialize_backend(&kernel_directory) {
        Ok(backend) => eprintln!("Proof backend: {backend}"),
        Err(error) => {
            eprintln!("Cannot initialize the proof backend: {error}");
            std::process::exit(1);
        }
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
