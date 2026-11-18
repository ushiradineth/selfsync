//! `selfsync` — сервер синхронизации заметок.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use selfsync_server::config::parse_duration;
use selfsync_server::gc::GcOptions;
use selfsync_server::modes::{self, cgi};
use selfsync_server::{AppState, Config, Mode, cmd, init_logging};

#[derive(Parser)]
#[command(
    name = "selfsync",
    version,
    about = "Self-hosted note synchronization server"
)]
struct Cli {
    /// Data directory (SELFSYNC_DATA_DIR, $STATE_DIRECTORY or /var/lib/selfsync).
    #[arg(long, global = true)]
    data: Option<PathBuf>,
    /// TOML configuration file (environment variables take precedence).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a persistent server process (Docker or development).
    Serve {
        /// Listen address: 127.0.0.1:8085 or unix:/path/to.sock.
        #[arg(long, default_value = "127.0.0.1:8085")]
        listen: String,
        /// Exit after this idle duration, e.g. 10m (0 disables).
        #[arg(long)]
        idle_timeout: Option<String>,
    },
    /// Run with systemd socket activation and idle shutdown.
    Socket {
        #[arg(long)]
        idle_timeout: Option<String>,
    },
    /// Handle one CGI request (also detected via GATEWAY_INTERFACE).
    Cgi,
    /// Upgrade database schemas to the current version.
    Migrate {
        #[arg(long)]
        vault: Option<String>,
    },
    /// Manage vaults.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Manage device tokens.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Create a one-time connection link and terminal QR code.
    Link {
        #[arg(long)]
        vault: String,
        /// External server URL (otherwise SELFSYNC_PUBLIC_URL).
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        name: String,
        /// Read-only device: receives changes without uploading local edits.
        #[arg(long)]
        read_only: bool,
    },
    /// Import an existing folder as plaintext.
    Import {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        from: PathBuf,
    },
    /// Garbage collection; displays a plan by default.
    Gc {
        #[arg(long)]
        vault: Option<String>,
        /// Only display a plan (default).
        #[arg(long)]
        dry_run: bool,
        /// Confirm deletion.
        #[arg(long, conflicts_with = "dry_run")]
        yes: bool,
        /// Always retain this many recent file revisions.
        #[arg(long, default_value_t = 20)]
        keep_revisions: u64,
        /// Never remove revisions younger than this many days.
        #[arg(long, default_value_t = 30)]
        keep_days: u64,
    },
    /// Purge deleted files whose retention has expired (for systemd timers).
    Sweep,
    /// Create a consistent backup. Without --copy, blobs share inodes with storage, so disk corruption affects both. --rotate ROOT --keep N stores timestamped backups and removes older copies.
    Backup {
        /// Empty destination directory (or use --rotate).
        #[arg(required_unless_present = "rotate", conflicts_with = "rotate")]
        dir: Option<PathBuf>,
        /// Copy blobs instead of sharing inodes with storage.
        #[arg(long)]
        copy: bool,
        /// Root directory for timestamped, rotating backups.
        #[arg(long, value_name = "ROOT")]
        rotate: Option<PathBuf>,
        /// Number of recent backups to retain during rotation.
        #[arg(long, requires = "rotate", default_value_t = 7)]
        keep: usize,
    },
    /// Verify databases, blob hashes and missing blobs. Exit codes: 0 clean, 1 problems found, 2 startup error.
    Verify {
        #[arg(long)]
        vault: Option<String>,
        /// Restore damaged or missing blobs from a selfsync backup.
        #[arg(long)]
        repair_from: Option<PathBuf>,
        /// Only print problems (for timers).
        #[arg(long)]
        quiet: bool,
    },
    /// Check installation: data, disk, databases, URL, proxy, timers, backups, verification and quotas. Exit 0 if there are no failures (warnings allowed), 1 on failure.
    Doctor {
        /// Backup directory used by selfsync backup --rotate.
        #[arg(long, default_value = "/var/lib/selfsync-backups")]
        backup_dir: PathBuf,
    },
    /// Health check for HEALTHCHECK (exit 0 or 1).
    Healthcheck {
        #[arg(
            long,
            env = "SELFSYNC_HEALTHCHECK_URL",
            default_value = "http://127.0.0.1:8085/v1/health"
        )]
        url: String,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// List vaults.
    List,
    /// View or update vault quotas. 0 means unlimited; default uses server configuration.
    Quota {
        #[arg(long)]
        vault: String,
        /// Storage warning threshold (e.g. 5GiB).
        #[arg(long)]
        soft: Option<String>,
        /// Stop accepting new files above this threshold.
        #[arg(long)]
        hard: Option<String>,
        /// Maximum active devices.
        #[arg(long)]
        devices: Option<String>,
        /// Maximum file size (at most SELFSYNC_MAX_BLOB_SIZE).
        #[arg(long)]
        max_file: Option<String>,
    },
    /// Regenerate database identity after restoring a filesystem snapshot or other non-selfsync backup. Devices reconcile fully. Without --vault, regenerate every vault.
    Regenerate {
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Issue a token for a new device (vault created on first use).
    Add {
        #[arg(long)]
        vault: String,
        #[arg(long)]
        name: String,
        /// Read-only device: receives changes without uploading local edits.
        #[arg(long)]
        read_only: bool,
    },
    /// List devices.
    List {
        #[arg(long)]
        vault: Option<String>,
    },
    /// Revoke a device (across all vaults unless --vault is specified).
    Revoke {
        #[arg(long)]
        name: String,
        #[arg(long)]
        vault: Option<String>,
    },
}

fn idle(flag: Option<String>, config: &Config, default: Duration) -> anyhow::Result<Duration> {
    match flag {
        Some(s) => parse_duration(&s),
        None => Ok(config.idle_timeout.unwrap_or(default)),
    }
}

fn run() -> anyhow::Result<ExitCode> {
    // fcgiwrap запускает бинарь без аргументов: CGI определяется по окружению.
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 && cgi::detected() {
        let config = Config::load(None, None)?;
        init_logging(&config.log);
        cgi::run(AppState::new(config, Mode::Cgi))?;
        return Ok(ExitCode::SUCCESS);
    }
    let cli = Cli::parse();
    let config = match Config::load(cli.config.as_deref(), cli.data.clone()) {
        Ok(c) => c,
        // У verify код 1 занят под «найдены проблемы»: ошибка запуска — 2.
        Err(e) if matches!(cli.cmd, Some(Cmd::Verify { .. })) => {
            eprintln!("error: {e:#}");
            return Ok(ExitCode::from(2));
        }
        Err(e) => return Err(e),
    };
    let Some(command) = cli.cmd else {
        use clap::CommandFactory;
        Cli::command().print_help()?;
        return Ok(ExitCode::from(2));
    };
    init_logging(&config.log);
    match command {
        Cmd::Cgi => cgi::run(AppState::new(config, Mode::Cgi))?,
        Cmd::Serve {
            listen,
            idle_timeout,
        } => {
            let idle = idle(idle_timeout, &config, Duration::ZERO)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move {
                let l = modes::bind(&listen).await?;
                modes::run(AppState::new(config, Mode::Serve), l, idle).await
            })?;
        }
        Cmd::Socket { idle_timeout } => {
            let idle = idle(idle_timeout, &config, Duration::from_secs(600))?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move {
                let l = modes::from_systemd()?;
                modes::run(AppState::new(config, Mode::Socket), l, idle).await
            })?;
        }
        Cmd::Migrate { vault } => cmd::migrate(&config, vault.as_deref())?,
        Cmd::Vault(VaultCmd::List) => cmd::vault_list(&config)?,
        Cmd::Vault(VaultCmd::Regenerate { vault }) => {
            cmd::vault_regenerate(&config, vault.as_deref())?
        }
        Cmd::Vault(VaultCmd::Quota {
            vault,
            soft,
            hard,
            devices,
            max_file,
        }) => cmd::vault_quota(
            &config,
            &vault,
            &cmd::QuotaPatch {
                soft,
                hard,
                devices,
                max_file,
            },
        )?,
        Cmd::Token(TokenCmd::Add {
            vault,
            name,
            read_only,
        }) => cmd::token_add(&config, &vault, &name, read_only)?,
        Cmd::Token(TokenCmd::List { vault }) => cmd::token_list(&config, vault.as_deref())?,
        Cmd::Token(TokenCmd::Revoke { name, vault }) => {
            cmd::token_revoke(&config, vault.as_deref(), &name)?
        }
        Cmd::Link {
            vault,
            url,
            name,
            read_only,
        } => cmd::link(&config, &vault, url.as_deref(), &name, read_only)?,
        Cmd::Import { vault, from } => {
            let r = cmd::import(&config, &vault, &from, config.max_blob_size)
                .with_context(|| format!("import from {}", from.display()))?;
            println!(
                "imported {} files, {} unchanged, {} directories",
                r.files, r.unchanged, r.folders
            );
            for (p, why) in &r.skipped {
                println!("skipped: {p}: {why}");
            }
        }
        Cmd::Gc {
            vault,
            dry_run: _,
            yes,
            keep_revisions,
            keep_days,
        } => cmd::gc(
            &config,
            vault.as_deref(),
            GcOptions {
                keep_revisions,
                keep_days,
            },
            yes,
        )?,
        Cmd::Sweep => cmd::sweep(&config)?,
        Cmd::Backup {
            dir,
            copy,
            rotate,
            keep,
        } => match (dir, rotate) {
            (_, Some(root)) => cmd::backup_rotate(&config, &root, keep, copy)?,
            (Some(dir), None) => cmd::backup(
                &config,
                &dir,
                cmd::BlobSource {
                    copy,
                    previous: None,
                },
            )?,
            (None, None) => unreachable!("clap requires DIR or --rotate"),
        },
        Cmd::Verify {
            vault,
            repair_from,
            quiet,
        } => {
            return Ok(
                match cmd::verify(&config, vault.as_deref(), repair_from.as_deref(), quiet) {
                    Ok(true) => ExitCode::SUCCESS,
                    Ok(false) => ExitCode::from(1),
                    Err(e) => {
                        eprintln!("error: {e:#}");
                        ExitCode::from(2)
                    }
                },
            );
        }
        Cmd::Doctor { backup_dir } => {
            use selfsync_server::doctor::{self, Level, Options};
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis()),
            )
            .unwrap_or(i64::MAX);
            let opts = Options {
                backup_dir,
                ..Options::new(now)
            };
            let report = doctor::doctor(&config, &opts);
            for f in &report.findings {
                let mark = match f.level {
                    Level::Ok => "✓",
                    Level::Warn => "⚠",
                    Level::Fail => "✗",
                    Level::Skip => "–",
                };
                println!("{mark} {}: {}", f.what, f.text);
            }
            return Ok(if report.failed() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            });
        }
        Cmd::Healthcheck { url } => {
            return Ok(if cmd::healthcheck(&url) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
