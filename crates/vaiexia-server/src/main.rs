use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal CLI: optional `--config <path>` and `reset-admin` subcommand.
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut reset_admin = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config_path = args.next().map(PathBuf::from);
            }
            "reset-admin" => {
                reset_admin = true;
            }
            _ => {}
        }
    }

    if reset_admin {
        vaiexia_server::reset_admin(config_path)?;
    } else {
        vaiexia_server::run(config_path).await?;
    }
    Ok(())
}
