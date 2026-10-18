fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [mode] if mode == "security" => bfv_complete_relinearization::demo::security(),
        [mode] if mode == "prove" => bfv_complete_relinearization::demo::prove_stream(),
        _ => {
            eprintln!("usage: bfv-complete-relinearization <security|prove>");
            std::process::exit(1);
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
