use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal CLI: optional `--config <path>` (full CLI layer is a later step).
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        if a == "--config" {
            config_path = args.next().map(PathBuf::from);
        }
    }
    vaiexia_server::run(config_path).await
}
