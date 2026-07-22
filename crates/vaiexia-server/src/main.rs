use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI: optional `--config <path>`, `reset-admin`, `--check-config`, `--version`.
    // Unknown flags print a usage line to stderr and exit 2 (avoids silent typos
    // that would start the daemon with unexpected defaults — a real footgun).
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut reset_admin = false;
    let mut check_config = false;
    let mut version = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config_path = args.next().map(PathBuf::from);
            }
            "reset-admin" => {
                reset_admin = true;
            }
            "--check-config" => {
                check_config = true;
            }
            "--version" => {
                version = true;
            }
            other => {
                eprintln!(
                    "error: unknown argument `{other}`\n\
                     usage: vaiexia-server [--config <path>] [--check-config] [--version] [reset-admin]"
                );
                std::process::exit(2);
            }
        }
    }

    if version {
        println!("vaiexia-server {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if check_config {
        if let Err(e) = vaiexia_server::check_config(config_path) {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if reset_admin {
        vaiexia_server::reset_admin(config_path)?;
    } else {
        vaiexia_server::run(config_path).await?;
    }
    Ok(())
}
