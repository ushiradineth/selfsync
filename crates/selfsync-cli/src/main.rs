use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use selfsync_cli::config::{Config, STATE_DIR};
use selfsync_cli::handoff;
use selfsync_cli::runner::{self, Options, Outcome, Session, VaultCommand};
use selfsync_core::engine::{
    ConflictChoice, DiagCheck, DiagLevel, Event, QuotaStatus, StorageHealth, UiCommand, UiResult,
};
use selfsync_core::index::Index;

#[derive(Parser)]
#[command(
    name = "selfsync-cli",
    version,
    about = "Synchronize a folder with a selfsync server"
)]
struct Cli {
    /// Folder to synchronize.
    #[arg(long, global = true, default_value = ".")]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect a folder using a token from selfsync token add.
    Init {
        #[arg(long)]
        server: String,
        #[arg(long, env = "SELFSYNC_TOKEN")]
        token: String,
        /// Device name (defaults to hostname).
        #[arg(long)]
        name: Option<String>,
        /// Use long polling with a persistent server (socket/serve).
        #[arg(long)]
        use_wait: bool,
    },
    /// Connect using a one-time code from selfsync link or selfsync-cli join. With a terminal, the source device can transfer the encryption key without a password.
    Connect {
        #[arg(long, required_unless_present = "link")]
        server: Option<String>,
        #[arg(long, required_unless_present = "link")]
        code: Option<String>,
        /// Connection link instead of --server and --code: https://.../join/<code> or an obsidian://selfsync-connect QR link.
        #[arg(long, conflicts_with_all = ["server", "code"])]
        link: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        use_wait: bool,
        /// Skip encryption-key handoff; enter the password during run.
        #[arg(long)]
        no_handoff: bool,
    },
    /// Create a one-time code, link and QR code for another device. With a terminal and an unlocked key, approve key handoff to the new device. The QR secret remains in terminal scrollback; keep the terminal private.
    Join {
        /// New device name (can be changed when connecting).
        #[arg(long, default_value = "new device")]
        name: String,
        /// Connect a read-only device.
        #[arg(long)]
        read_only: bool,
        /// Encryption password file (or SELFSYNC_PASSWORD) if no key is remembered.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Create a code without transferring the encryption key.
        #[arg(long)]
        no_handoff: bool,
    },
    /// Synchronize and watch until Ctrl-C, or run one cycle with --once.
    Run {
        #[arg(long)]
        once: bool,
        /// Encryption password file (or SELFSYNC_PASSWORD).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Do not remember the key in .selfsync/key.
        #[arg(long)]
        no_remember: bool,
        /// Shell command after each cycle with changes; runs in the folder with SELFSYNC_DIR, SELFSYNC_PULLED, SELFSYNC_PUSHED and SELFSYNC_CHANGES_FILE. Defaults to exec in .selfsync/config.toml.
        #[arg(long)]
        exec: Option<String>,
        /// Stop hooks exceeding this duration (default 10m).
        #[arg(long)]
        exec_timeout: Option<String>,
        /// Confirm deletions blocked because many previously present files were missing (filesystem failure safeguard).
        #[arg(long)]
        allow_deletes: bool,
        /// Hash every file instead of trusting size and modification time; unnoticed changes are synced as ordinary edits.
        #[arg(long)]
        verify_content: bool,
    },
    /// Enable end-to-end vault encryption (every device will need the password).
    Encrypt {
        /// Password file (or SELFSYNC_PASSWORD).
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Also create a recovery phrase (24 words printed once). Key record becomes format 2; upgrade plugin and CLI 0.1.x devices first.
        #[arg(long)]
        recovery: bool,
    },
    /// Manage the encrypted vault recovery phrase.
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Recover a forgotten password using the recovery phrase and set a new password.
    Recover {
        /// File containing 24 words (otherwise prompt in terminal).
        #[arg(long)]
        phrase_file: Option<PathBuf>,
        /// File containing the new password (otherwise prompt in terminal).
        #[arg(long)]
        new_password_file: Option<PathBuf>,
        /// Do not remember the key in .selfsync/key.
        #[arg(long)]
        no_remember: bool,
    },
    /// Rotate the encryption key after revoking a device. Re-encrypts the vault under a new key with the same password; other devices ask for the password again.
    Rekey {
        /// Password file (or SELFSYNC_PASSWORD).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Show connection, pending changes and conflicts.
    Status,
    /// Check address, certificate, proxy, version, clock, token, request limits and long polling without syncing. Exit 1 on failure.
    Check,
    /// Show server file history (revision, date, size and device).
    History {
        /// Path inside the folder.
        path: String,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Show deleted files in server trash and their expiration times.
    Trash {
        /// Include expired files (removed by the next sweep).
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Restore files from server trash.
    Restore {
        #[arg(required = true)]
        paths: Vec<String>,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Permanently erase files and their history from server trash.
    Purge {
        #[arg(required = true)]
        paths: Vec<String>,
        /// Confirm permanent deletion.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Remove old server revisions to free space; retains the current revision and the last revision before deletion.
    PurgeHistory {
        path: String,
        /// Remove revisions before this revision (default: all old revisions).
        #[arg(long)]
        before: Option<u64>,
        /// Confirm permanent deletion.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Restore a file revision, preserving unsent local changes as a nearby copy.
    Revert {
        path: String,
        #[arg(long)]
        rev: u64,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// List unresolved conflicts.
    Conflicts {
        #[command(flatten)]
        v: VaultArgs,
    },
    /// List files skipped because of max_download_size.
    Skipped {
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Download a skipped file despite the size limit, then continue syncing it.
    Download {
        path: String,
        #[command(flatten)]
        v: VaultArgs,
    },
    /// Resolve a conflict: keep both, local or server version.
    Resolve {
        id: u64,
        #[arg(long, value_enum)]
        keep: Keep,
        #[command(flatten)]
        v: VaultArgs,
    },
}

/// First released version supporting format 2 key records with recovery phrases.
const RECOVERY_MIN: &str = "0.2.1";
/// First version supporting key rotation, epochs and format 3 key records.
const REKEY_MIN: &str = "0.3.0";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SELFSYNC_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(real_main(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn real_main(cli: Cli) -> anyhow::Result<ExitCode> {
    let dir = cli.dir;
    match cli.cmd {
        Cmd::History { path, v } => {
            let path = vault_path(&dir, &path);
            let cmd = VaultCommand::Ui(UiCommand::History { path: path.clone() });
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::History { revisions } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&revisions);
                }
                if revisions.is_empty() {
                    println!("{path} has no server history");
                }
                for x in revisions {
                    let what = if x.deleted {
                        "deleted".to_owned()
                    } else {
                        format!("{} bytes", x.size)
                    };
                    let from = x
                        .renamed_from
                        .map(|f| format!(" (of {f})"))
                        .unwrap_or_default();
                    println!(
                        "{}\t{}\t{what}\t#{}{from}",
                        x.rev,
                        fmt_time(x.mtime),
                        x.device
                    );
                }
                Ok(())
            })
            .await;
        }
        Cmd::Trash { all, v } => {
            let cmd = VaultCommand::Ui(UiCommand::ListDeleted);
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis()),
            )
            .unwrap_or(i64::MAX);
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Deleted { items } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                let items: Vec<_> = items
                    .into_iter()
                    .filter(|x| all || x.expires_at > now)
                    .collect();
                if json {
                    return print_json(&items);
                }
                if items.is_empty() {
                    println!("trash is empty");
                }
                for x in items {
                    println!(
                        "{}\tdeleted {}\tpurge after {}\t{} bytes",
                        x.path,
                        fmt_time(x.deleted_at),
                        fmt_time(x.expires_at),
                        x.size
                    );
                }
                Ok(())
            })
            .await;
        }
        Cmd::Restore { paths, v } => {
            let paths = paths.iter().map(|p| vault_path(&dir, p)).collect();
            let cmd = VaultCommand::Ui(UiCommand::RestoreDeleted { paths });
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Restored { count } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&serde_json::json!({ "count": count }));
                }
                println!("restored: {count}");
                Ok(())
            })
            .await;
        }
        Cmd::Purge { paths, yes, v } => {
            if !yes {
                anyhow::bail!("purging trash is irreversible; add --yes");
            }
            let paths = paths.iter().map(|p| vault_path(&dir, p)).collect();
            let cmd = VaultCommand::Ui(UiCommand::PurgeDeleted {
                paths,
                seqs: Vec::new(),
            });
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Restored { count } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&serde_json::json!({ "count": count }));
                }
                println!("permanently deleted: {count}");
                Ok(())
            })
            .await;
        }
        Cmd::PurgeHistory {
            path,
            before,
            yes,
            v,
        } => {
            if !yes {
                anyhow::bail!("purging old revisions is irreversible; add --yes");
            }
            let path = vault_path(&dir, &path);
            let cmd = VaultCommand::Ui(UiCommand::PurgeHistory {
                path: path.clone(),
                before_rev: before.unwrap_or(u64::MAX),
            });
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Restored { count } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&serde_json::json!({ "count": count }));
                }
                println!("{path}: purged {count} old revisions");
                Ok(())
            })
            .await;
        }
        Cmd::Revert { path, rev, v } => {
            let path = vault_path(&dir, &path);
            let cmd = VaultCommand::Ui(UiCommand::RestoreRevision {
                path: path.clone(),
                rev,
            });
            return vault_command(&dir, v, cmd, |_, json| {
                if json {
                    return print_json(&serde_json::json!({ "ok": true }));
                }
                println!("{path}: restored revision {rev}");
                Ok(())
            })
            .await;
        }
        Cmd::Conflicts { v } => {
            let cmd = VaultCommand::Ui(UiCommand::Conflicts);
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Conflicts { items } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&items);
                }
                if items.is_empty() {
                    println!("no conflicts");
                }
                for c in items {
                    println!("{}\t{}\tcopy {}\t{}", c.id, c.path, c.copy, fmt_time(c.at));
                }
                Ok(())
            })
            .await;
        }
        Cmd::Skipped { v } => {
            let cmd = VaultCommand::Ui(UiCommand::Skipped);
            return vault_command(&dir, v, cmd, |r, json| {
                let UiResult::Skipped { files } = r else {
                    anyhow::bail!("unexpected response: {r:?}");
                };
                if json {
                    return print_json(&files);
                }
                if files.is_empty() {
                    println!("no skipped files");
                }
                for f in files {
                    println!("{}\t{}", f.path, f.size);
                }
                Ok(())
            })
            .await;
        }
        Cmd::Download { path, v } => {
            let path = vault_path(&dir, &path);
            let cmd = VaultCommand::Ui(UiCommand::Download { path: path.clone() });
            // Команда ставит файл в очередь; скачивает его следующий цикл синка.
            let json = v.json;
            let code = vault_command(&dir, v, cmd, |_, _| Ok(())).await?;
            if code != ExitCode::SUCCESS {
                return Ok(code);
            }
            let ok = dir.join(&path).is_file();
            if json {
                print_json(&serde_json::json!({ "path": path, "downloaded": ok }))?;
            } else if ok {
                println!("downloaded: {path}");
            } else {
                eprintln!("{path}: download failed; see the log and retry later");
            }
            return Ok(if ok { code } else { ExitCode::from(1) });
        }
        Cmd::Resolve { id, keep, v } => {
            let choice = match keep {
                Keep::Both => ConflictChoice::KeepBoth,
                Keep::Mine => ConflictChoice::KeepMine,
                Keep::Server => ConflictChoice::KeepServer,
            };
            // Неизвестный id ядро молча пропускает — проверить заранее по индексу.
            let known = std::fs::read(dir.join(STATE_DIR).join("index.bin"))
                .ok()
                .and_then(|b| Index::decode(&b).ok())
                .is_some_and(|idx| idx.conflicts.iter().any(|c| c.id == id));
            if !known {
                anyhow::bail!(
                    "conflict {id} not found; list conflicts with selfsync-cli conflicts"
                );
            }
            let cmd = VaultCommand::Resolve { id, choice };
            return vault_command(&dir, v, cmd, |_, json| {
                if json {
                    return print_json(&serde_json::json!({ "ok": true }));
                }
                println!("conflict {id} resolved");
                Ok(())
            })
            .await;
        }
        Cmd::Init {
            server,
            token,
            name,
            use_wait,
        } => {
            std::fs::create_dir_all(&dir).with_context(|| format!("folder {}", dir.display()))?;
            let mut cfg = Config::load(&dir).unwrap_or_default();
            cfg.server = server.trim_end_matches('/').to_owned();
            cfg.token = token;
            cfg.use_wait = use_wait;
            if let Some(n) = name {
                cfg.device_name = n;
            }
            cfg.save(&dir)?;
            println!(
                "folder {} connected to {}; sync with: selfsync-cli run --dir {}",
                dir.display(),
                cfg.server,
                dir.display()
            );
        }
        Cmd::Connect {
            server,
            code,
            link,
            name,
            use_wait,
            no_handoff,
        } => {
            let (server, code, secret, check) = match link {
                Some(l) => {
                    let l = handoff::parse_link(&l).context(
                        "invalid link; expected https://.../join/<code> or obsidian://selfsync-connect?...",
                    )?;
                    (l.server, l.code, l.secret, l.check)
                }
                None => (
                    server.context("--server is required")?,
                    code.context("--code is required")?,
                    None,
                    None,
                ),
            };
            std::fs::create_dir_all(dir.join(STATE_DIR))?;
            let mut cfg = Config::load(&dir).unwrap_or_default();
            if let Some(n) = name {
                cfg.device_name = n;
            }
            let server = server.trim_end_matches('/').to_owned();
            let r = runner::command(
                &dir,
                &server,
                None,
                &cfg.device_name,
                UiCommand::Redeem {
                    code,
                    name: cfg.device_name.clone(),
                },
            )
            .await?;
            match r {
                UiResult::Token {
                    token,
                    vault,
                    device_name,
                    handoff: commit,
                    ..
                } => {
                    cfg.server = server;
                    cfg.token = token;
                    cfg.vault = vault.clone();
                    cfg.device_name = device_name;
                    cfg.use_wait = use_wait;
                    cfg.save(&dir)?;
                    println!("connected to vault {vault} as {}", cfg.device_name);
                    if commit.is_none() && check.is_some() {
                        // QR обещал обмен, а сервер обязательства не прислал: ключ так
                        // или иначе не примется — нейтрально, без догадок.
                        eprintln!(
                            "key handoff unavailable; enter the password during run. If the source device did not cancel, this may indicate tampering."
                        );
                    }
                    if let Some(commit) = commit {
                        if no_handoff || !handoff::interactive() {
                            eprintln!(
                                "source device can transfer the encryption key, but handoff is disabled or no terminal is available; enter the password during run"
                            );
                        } else {
                            let mut sess = Session::new(
                                &dir,
                                &cfg.server,
                                Some(cfg.token.clone()),
                                &cfg.device_name,
                            )?;
                            let deadline = now_ms() + handoff::WAIT_MS;
                            let got = handoff::receive_key(
                                &mut sess,
                                commit,
                                secret,
                                check,
                                deadline,
                                handoff::POLL,
                                &mut handoff::Terminal,
                            )
                            .await?;
                            match got {
                                handoff::Exchange::Done => {
                                    println!("encryption key saved in {STATE_DIR}/key");
                                }
                                handoff::Exchange::Refused => {
                                    eprintln!("key not received; enter the password during run");
                                }
                                handoff::Exchange::Interrupted => {
                                    eprintln!("interrupted; enter the password during run");
                                    // Чтение ответа в отдельном потоке не прервать —
                                    // выйти, не дожидаясь его.
                                    std::process::exit(130);
                                }
                            }
                        }
                    }
                }
                UiResult::Error {
                    code, retry_after, ..
                } if code == "rate_limited" => anyhow::bail!(
                    "too many incorrect codes from this address; wait {retry_after} s"
                ),
                UiResult::Error { message, .. } => {
                    anyhow::bail!("server refused request: {message}")
                }
                other => anyhow::bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Join {
            name,
            read_only,
            password_file,
            no_handoff,
        } => {
            let cfg = Config::load(&dir)?;
            let want = !no_handoff && handoff::interactive();
            let mut sess = Session::for_folder(&dir, &cfg)?;
            let key_saved = dir.join(STATE_DIR).join("key").is_file();
            if want
                && !key_saved
                && let Some(password) = read_password(password_file)?
            {
                sess.feed(Event::Password {
                    password,
                    remember: false,
                });
                sess.settle().await?;
            }
            let r = sess
                .command(UiCommand::CreateJoin {
                    name: name.clone(),
                    read_only,
                    handoff: want,
                })
                .await?;
            let (code, url, expires_at, secret, check) = match r {
                UiResult::Join {
                    code,
                    url,
                    expires_at,
                    secret,
                    check,
                } => (code, url, expires_at, secret, check),
                UiResult::Error { message, .. } => {
                    anyhow::bail!("server refused request: {message}")
                }
                other => anyhow::bail!("unexpected response: {other:?}"),
            };
            println!(
                "Connect {name}{} (one use, expires {}):",
                if read_only { " read-only" } else { "" },
                fmt_time(expires_at)
            );
            println!("{url}\n");
            // С обменом QR ведёт сразу в Obsidian и несёт секрет: сервер его не видит.
            let qr = match (&secret, &check) {
                (Some(m), Some(h)) => handoff::connect_link(&cfg.server, &code, m, h),
                _ => url.clone(),
            };
            print!("{}", handoff::render_qr(&qr)?);
            println!("\nManual connection code: {code}");
            println!(
                "Another folder: selfsync-cli connect --server {} --code {code}",
                cfg.server
            );
            if secret.is_some() {
                let deadline = expires_at + handoff::WAIT_MS;
                let given = handoff::give_key(
                    &mut sess,
                    &code,
                    deadline,
                    handoff::POLL,
                    &mut handoff::Terminal,
                )
                .await?;
                match given {
                    handoff::Exchange::Done => {}
                    handoff::Exchange::Refused => return Ok(ExitCode::from(1)),
                    // Чтение ответа в отдельном потоке не прервать — выйти сразу.
                    handoff::Exchange::Interrupted => std::process::exit(130),
                }
            } else if want {
                eprintln!(
                    "key handoff unavailable: vault is unencrypted, no key is available here (--password-file), or server is older than 0.5.0"
                );
            }
        }
        Cmd::Run {
            once,
            password_file,
            no_remember,
            exec,
            exec_timeout,
            allow_deletes,
            verify_content,
        } => {
            let cfg = Config::load(&dir)?;
            let hook = match exec.or_else(|| cfg.exec.clone()) {
                Some(command) if !command.trim().is_empty() => {
                    let timeout = match exec_timeout.or_else(|| cfg.exec_timeout.clone()) {
                        Some(t) => humantime::parse_duration(t.trim())
                            .with_context(|| format!("invalid hook timeout: {t}"))?,
                        None => selfsync_cli::hook::DEFAULT_TIMEOUT,
                    };
                    Some(selfsync_cli::hook::HookConfig { command, timeout })
                }
                _ => None,
            };
            let opts = Options {
                once,
                watch: true,
                password: read_password(password_file)?,
                remember_key: !no_remember,
                enable_encryption: false,
                hook,
                recovery: false,
                allow_deletes,
                verify_content,
            };
            return Ok(outcome(runner::run(&dir, &cfg, opts).await?));
        }
        Cmd::Recovery(rc) => {
            let (password_file, create) = match rc {
                RecoveryCmd::Create { password_file } => (password_file, true),
                RecoveryCmd::Remove { password_file } => (password_file, false),
            };
            let password = read_password(password_file)?
                .context("password required: --password-file or SELFSYNC_PASSWORD")?;
            let cmd = if create {
                UiCommand::CreateRecovery {
                    password: password.clone(),
                }
            } else {
                UiCommand::RemoveRecovery {
                    password: password.clone(),
                }
            };
            // Пароль нужен и синку перед командой, если ключ ещё не запомнен.
            let cfg = Config::load(&dir)?;
            if create {
                warn_old_devices(&dir, &cfg, RECOVERY_MIN, "key record with recovery phrase").await;
            }
            let (o, r) =
                runner::with_vault(&dir, &cfg, Some(password), true, VaultCommand::Ui(cmd)).await?;
            return match r {
                Some(UiResult::RecoveryPhrase { words }) => {
                    runner::print_phrase(&words);
                    eprintln!(
                        "Key record now uses format 2; devices need a plugin or CLI supporting recovery phrases."
                    );
                    Ok(outcome(o))
                }
                Some(UiResult::Ok) => {
                    println!("recovery phrase removed");
                    Ok(outcome(o))
                }
                Some(UiResult::Error { message, .. }) => {
                    eprintln!("error: {message}");
                    Ok(ExitCode::from(1))
                }
                Some(other) => anyhow::bail!("unexpected response: {other:?}"),
                None => Ok(outcome(o)),
            };
        }
        Cmd::Recover {
            phrase_file,
            new_password_file,
            no_remember,
        } => {
            let cfg = Config::load(&dir)?;
            let phrase = read_secret(phrase_file, "recovery phrase (24 words)")?;
            // Проверка до сети: номер неверного слова сразу.
            if let Err(e) = selfsync_core::crypto::RecoveryEntropy::from_phrase(&phrase) {
                anyhow::bail!("phrase: {e}");
            }
            let new_password = read_secret(new_password_file, "new password")?;
            anyhow::ensure!(!new_password.is_empty(), "empty password");
            let r = runner::folder_command(
                &dir,
                &cfg,
                UiCommand::Recover {
                    phrase,
                    new_password: new_password.clone(),
                    remember: !no_remember,
                },
            )
            .await?;
            if let UiResult::Error { message, .. } = r {
                eprintln!("error: {message}");
                return Ok(ExitCode::from(1));
            }
            eprintln!("access recovered and password replaced; syncing...");
            let opts = Options {
                once: true,
                watch: false,
                password: Some(new_password),
                remember_key: !no_remember,
                enable_encryption: false,
                hook: None,
                recovery: false,
                allow_deletes: false,
                verify_content: false,
            };
            return Ok(outcome(runner::run(&dir, &cfg, opts).await?));
        }
        Cmd::Encrypt {
            password_file,
            recovery,
        } => {
            let cfg = Config::load(&dir)?;
            let password = read_password(password_file)?
                .context("password required: --password-file or SELFSYNC_PASSWORD")?;
            if recovery {
                warn_old_devices(&dir, &cfg, RECOVERY_MIN, "key record with recovery phrase").await;
            }
            let opts = Options {
                once: true,
                watch: false,
                password: Some(password),
                remember_key: true,
                enable_encryption: true,
                hook: None,
                recovery,
                allow_deletes: false,
                verify_content: false,
            };
            let code = outcome(runner::run(&dir, &cfg, opts).await?);
            if code == ExitCode::SUCCESS {
                println!("encryption enabled; other devices will need this password");
            }
            return Ok(code);
        }
        Cmd::Rekey { password_file } => {
            let password = read_password(password_file)?
                .context("password required: --password-file or SELFSYNC_PASSWORD")?;
            let cfg = Config::load(&dir)?;
            warn_old_devices(&dir, &cfg, REKEY_MIN, "key rotation").await;
            let cmd = UiCommand::Rekey {
                password: password.clone(),
                remember: true,
            };
            let (o, r) =
                runner::with_vault(&dir, &cfg, Some(password), true, VaultCommand::Ui(cmd)).await?;
            return match r {
                Some(UiResult::Ok) if o == Outcome::Synced => {
                    println!("encryption key rotated; other devices will need the password");
                    Ok(outcome(o))
                }
                Some(UiResult::Ok) => {
                    eprintln!("re-encryption is incomplete; the next `run` will resume it");
                    Ok(outcome(o))
                }
                Some(UiResult::Error { message, .. }) => {
                    eprintln!("error: {message}");
                    Ok(ExitCode::from(1))
                }
                _ => Ok(outcome(o)),
            };
        }
        Cmd::Check => {
            let cfg = Config::load(&dir)?;
            let r = runner::folder_command(&dir, &cfg, UiCommand::Diagnose).await?;
            let UiResult::Diagnosis { checks } = r else {
                anyhow::bail!("unexpected response: {r:?}");
            };
            let mut failed = false;
            for c in &checks {
                failed |= c.level == DiagLevel::Fail;
                let mark = match c.level {
                    DiagLevel::Ok => "✓",
                    DiagLevel::Warn => "⚠",
                    DiagLevel::Fail => "✗",
                    DiagLevel::Skip => "–",
                };
                println!("{mark} {}: {}", diag_step(&c.step), diag_text(c));
            }
            return Ok(if failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            });
        }
        Cmd::Status => {
            let cfg = Config::load(&dir)?;
            println!("server:     {}", cfg.server);
            println!(
                "vault:      {}",
                if cfg.vault.is_empty() {
                    "?"
                } else {
                    &cfg.vault
                }
            );
            println!("device:     {}", cfg.device_name);
            if dir.join(".git").exists()
                && !selfsync_core::exclude::Excludes::new(&cfg.excludes).is_excluded(".git/HEAD")
            {
                println!(
                    "warning:    .git is not excluded; the repository will sync to all devices; add .git/ to excludes in {}",
                    Config::path(&dir).display()
                );
            }
            match std::fs::read(dir.join(STATE_DIR).join("index.bin"))
                .ok()
                .map(|b| Index::decode(&b))
            {
                Some(Ok(idx)) => {
                    let files = idx
                        .files
                        .values()
                        .filter(|f| !f.folder && f.local.is_some())
                        .count();
                    println!("files:      {files}");
                    println!("pending:    {}", idx.pending_count());
                    println!(
                        "encryption: {}",
                        if matches!(idx.mode, selfsync_core::index::VaultMode::Plain) {
                            "none"
                        } else {
                            "да"
                        }
                    );
                    println!("cursor:     {}", idx.last_seq);
                    if dir.join(STATE_DIR).join(runner::READ_ONLY_MARKER).exists() {
                        println!("mode:       read-only (local edits are not uploaded)");
                    }
                    if let Some(s) = std::fs::read(dir.join(STATE_DIR).join(runner::SERVER_MARKER))
                        .ok()
                        .and_then(|b| serde_json::from_slice::<runner::ServerState>(&b).ok())
                    {
                        if s.storage != StorageHealth::default() {
                            println!("storage:    {}", storage_line(&s.storage));
                        }
                        if let Some(q) = quota_line(&s.quota) {
                            println!("quota:      {q}");
                        }
                    }
                    for c in &idx.conflicts {
                        println!("conflict:   {} -> copy {}", c.path, c.copy);
                    }
                }
                Some(Err(e)) => println!("index:      damaged ({e})"),
                None => println!("index:      not synced yet"),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Create a recovery phrase, replacing and invalidating any previous phrase.
    Create {
        /// Password file (or SELFSYNC_PASSWORD).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Remove the recovery phrase.
    Remove {
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

/// Read a secret from a file or terminal without echo.
fn read_secret(file: Option<PathBuf>, prompt: &str) -> anyhow::Result<String> {
    if let Some(p) = file {
        return Ok(std::fs::read_to_string(&p)
            .with_context(|| format!("{}", p.display()))?
            .trim()
            .to_owned());
    }
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    anyhow::ensure!(
        stdin.is_terminal(),
        "no terminal; provide a file ({prompt})"
    );
    eprint!("{prompt}: ");
    std::io::stderr().flush()?;
    let _echo = EchoOff::new();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    eprintln!();
    Ok(line.trim().to_owned())
}

/// Disable terminal echo while reading a secret.
struct EchoOff(#[cfg(unix)] Option<libc::termios>);

impl EchoOff {
    fn new() -> EchoOff {
        #[cfg(unix)]
        {
            // SAFETY: tcgetattr/tcsetattr над stdin; структура заполняется ОС.
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(0, &mut t) == 0 {
                    let old = t;
                    t.c_lflag &= !libc::ECHO;
                    libc::tcsetattr(0, libc::TCSANOW, &t);
                    return EchoOff(Some(old));
                }
            }
            EchoOff(None)
        }
        #[cfg(not(unix))]
        EchoOff()
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(t) = self.0 {
            // SAFETY: восстановление сохранённых атрибутов терминала.
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
}

/// Shared arguments for history and trash commands.
#[derive(Args)]
struct VaultArgs {
    /// Print JSON for scripts.
    #[arg(long)]
    json: bool,
    /// Encryption password file (or SELFSYNC_PASSWORD).
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// Do not remember the key in .selfsync/key.
    #[arg(long)]
    no_remember: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Keep {
    Both,
    Mine,
    Server,
}

/// Normalize a relative or absolute in-folder path to a vault path.
fn vault_path(dir: &std::path::Path, p: &str) -> String {
    let path = std::path::Path::new(p);
    let rel = if path.is_absolute() {
        let base = dir.canonicalize().unwrap_or_else(|_| dir.to_owned());
        let full = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        full.strip_prefix(&base)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_owned())
    } else {
        p.to_owned()
    };
    let rel = rel.replace('\\', "/");
    rel.trim_start_matches("./").trim_matches('/').to_owned()
}

fn diag_step(step: &str) -> &str {
    match step {
        "server" => "server",
        "proxy" => "proxy",
        "version" => "version",
        "clock" => "clock",
        "token" => "token",
        "body" => "large requests",
        "longpoll" => "long-poll",
        other => other,
    }
}

/// Explain a connection-check result and remediation.
fn diag_text(c: &DiagCheck) -> String {
    let d = &c.detail;
    match (c.step.as_str(), c.code.as_str()) {
        ("server", "ok") => format!("responding, selfsync {d}"),
        (_, "tls") => "certificate rejected: self-signed, expired or issued for another hostname; use a trusted certificate such as Let's Encrypt for this address"
            .into(),
        (_, "dns") => "server name not found; check the address".into(),
        (_, "refused") => "connection refused; server is stopped or port is closed".into(),
        (_, "timeout") => {
            "server did not respond; address is unreachable or blocked from this network".into()
        }
        (_, "network") => format!("network: {d}"),
        (_, "not_selfsync") => {
            format!("address does not serve selfsync ({d}); check the URL and proxy path")
        }
        (_, "headers_stripped") => "proxy or CDN strips x-selfsync-proto response headers; the client cannot determine the server version"
            .into(),
        (_, "proto_major") => {
            format!("server uses a different protocol version ({d}); upgrade the client or server")
        }
        (_, "server_old") => {
            format!("server {d} is older than the client; some features are unavailable; upgrade the server")
        }
        ("version", "ok") => format!("matches ({d})"),
        (_, "skew") => format!("clock differs from server by {d} s; check system time"),
        (_, "no_date") => "server did not report its time".into(),
        ("token", "ok") => "accepted".into(),
        ("token", "read_only") => "accepted, device is read-only".into(),
        (_, "unauthorized") => {
            "rejected: device revoked or token invalid; connect again".into()
        }
        (_, "client_old") => "server requires a newer client; upgrade selfsync-cli".into(),
        (_, "rate_limited") => "server temporarily rate-limited attempts; retry later".into(),
        ("body", "ok") => "accepted".into(),
        (_, "server_limit") => "accepted up to the server file-size limit".into(),
        (_, "body_limit") => format!(
            "proxy rejects requests over about 1.5 MiB ({d}); raise its limit (nginx: client_max_body_size 32m)"
        ),
        (_, "quota") => "not checked: vault storage is full".into(),
        ("body", "read_only") => "not checked on read-only devices".into(),
        (_, "unexpected") => format!("unexpected response ({d})"),
        ("longpoll", "ok") => "working".into(),
        (_, "off") => "disabled (use_wait = false); changes are discovered by polling".into(),
        (_, "changed") => "not checked: vault changed during the check".into(),
        (_, "no_longpoll") => "server replies immediately (CGI or proxy); disable use_wait in .selfsync/config.toml"
            .into(),
        (_, "failed") => format!(
            "request interrupted ({d}); proxy closes long requests; raise its timeout (nginx: proxy_read_timeout 60s) or disable use_wait"
        ),
        ("clock", "ok") | ("proxy", "ok") => "OK".into(),
        (_, code) => format!("{code} {d}"),
    }
}

/// Format the last synced vault quota for status; None for servers before 0.4.0.
fn quota_line(q: &QuotaStatus) -> Option<String> {
    if *q == QuotaStatus::default() {
        return None;
    }
    let mut s = format!("{} used", fmt_bytes(q.used));
    if q.hard > 0 {
        s.push_str(&format!(" of {}", fmt_bytes(q.hard)));
    }
    if q.soft > 0 {
        s.push_str(&format!(", warning threshold {}", fmt_bytes(q.soft)));
    }
    if q.held > 0 {
        s.push_str(&format!(
            "; storage full, {} awaiting upload (purge, purge-history)",
            q.held
        ));
    }
    Some(s)
}

fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", U[0])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Format the last synced server storage health for status.
fn storage_line(s: &StorageHealth) -> String {
    let mut parts = Vec::new();
    if s.damaged > 0 {
        parts.push(format!(
            "{} damaged files, awaiting copies from devices",
            s.damaged
        ));
    }
    if s.server_problem {
        parts.push("damage requiring an administrator (selfsync verify)".to_owned());
    }
    if parts.is_empty() {
        parts.push("no problems".to_owned());
    }
    if s.verified_at > 0 {
        parts.push(format!("verified {}", fmt_time(s.verified_at)));
    }
    parts.join("; ")
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn fmt_time(ms: i64) -> String {
    if ms <= 0 {
        return "—".to_owned();
    }
    let t =
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(ms).unwrap_or(0));
    humantime::format_rfc3339_seconds(t).to_string()
}

fn print_json<T: serde::Serialize>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

/// Execute a vault command; print its result and use run --once exit codes.
async fn vault_command(
    dir: &std::path::Path,
    v: VaultArgs,
    cmd: VaultCommand,
    print: impl FnOnce(UiResult, bool) -> anyhow::Result<()>,
) -> anyhow::Result<ExitCode> {
    let cfg = Config::load(dir)?;
    let (o, r) = runner::with_vault(
        dir,
        &cfg,
        read_password(v.password_file)?,
        !v.no_remember,
        cmd,
    )
    .await?;
    match r {
        Some(UiResult::Error { code, message, .. }) => {
            if v.json {
                print_json(&serde_json::json!({ "error": code, "message": message }))?;
            }
            eprintln!("error: {message}");
            Ok(ExitCode::from(1))
        }
        Some(r) => {
            print(r, v.json)?;
            Ok(outcome(o))
        }
        None => Ok(outcome(o)),
    }
}

/// Warn about devices older than min or of unknown version before an incompatible operation; silent when offline.
async fn warn_old_devices(dir: &std::path::Path, cfg: &Config, min: &str, what: &str) {
    let Ok(UiResult::Devices { devices, .. }) =
        runner::folder_command(dir, cfg, UiCommand::Devices).await
    else {
        return;
    };
    let old: Vec<String> = devices
        .iter()
        .filter(|d| !d.revoked && !d.current)
        .filter(|d| selfsync_core::version::older_than(&d.client, min))
        .map(|d| {
            if d.client.is_empty() {
                format!("{} (unknown version)", d.name)
            } else {
                format!("«{}» ({})", d.name, d.client)
            }
        })
        .collect();
    if !old.is_empty() {
        eprintln!(
            "warning: {what} is not supported by devices older than {min}: {}; upgrade their plugin or selfsync-cli",
            old.join(", ")
        );
    }
}

fn read_password(file: Option<PathBuf>) -> anyhow::Result<Option<String>> {
    Ok(match file {
        Some(p) => Some(
            std::fs::read_to_string(&p)
                .with_context(|| format!("password from {}", p.display()))?
                .trim_end_matches(['\n', '\r'])
                .to_owned(),
        ),
        None => std::env::var("SELFSYNC_PASSWORD").ok(),
    })
}

fn outcome(o: Outcome) -> ExitCode {
    match o {
        Outcome::Synced | Outcome::Interrupted => ExitCode::SUCCESS,
        Outcome::Failed(r) => {
            eprintln!("sync failed: {r}");
            ExitCode::from(1)
        }
        Outcome::NeedPassword => {
            eprintln!(
                "vault is encrypted; password required (--password-file or SELFSYNC_PASSWORD)"
            );
            ExitCode::from(2)
        }
        Outcome::Blocked(r) if r == "mass_delete" => {
            eprintln!(
                "sync stopped: many previously present files are missing; no deletions were sent. Restore the files or confirm with run --allow-deletes."
            );
            ExitCode::from(3)
        }
        Outcome::Blocked(r) => {
            eprintln!("sync stopped: {r}");
            ExitCode::from(3)
        }
    }
}
