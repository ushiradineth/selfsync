//! `GET /metrics` — метрики в текстовом формате Prometheus. Только с токеном из
//! `SELFSYNC_METRICS_TOKEN`; без него в конфигурации маршрута как будто нет.
//!
//! Счётчики событий хранятся в `server.db`, а не в памяти: сервер, запущенный по
//! сокету, выходит по простою, и счётчик в памяти терял бы всё между опросами.

use std::fmt::Write as _;

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use selfsync_core::hash::Hash;
use subtle::ConstantTimeEq;

use super::bearer;
use crate::db::server::{blocked_now, counters, list_devices};
use crate::db::vault::{meta_int, stats, vault_state};
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, list_vault_dirs};

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Значение метки: `\`, `"` и перевод строки экранируются.
fn label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Текст метрик: `# HELP`/`# TYPE` один раз на метрику, затем строки.
#[derive(Default)]
struct Out {
    text: String,
    declared: Vec<&'static str>,
}

impl Out {
    fn metric(
        &mut self,
        name: &'static str,
        kind: &str,
        help: &str,
        labels: &[(&str, &str)],
        v: f64,
    ) {
        if !self.declared.contains(&name) {
            self.declared.push(name);
            let _ = writeln!(self.text, "# HELP {name} {help}");
            let _ = writeln!(self.text, "# TYPE {name} {kind}");
        }
        self.text.push_str(name);
        if !labels.is_empty() {
            self.text.push('{');
            for (i, (k, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.text.push(',');
                }
                let _ = write!(self.text, "{k}=\"{}\"", label(val));
            }
            self.text.push('}');
        }
        let _ = writeln!(self.text, " {v}");
    }

    fn gauge(&mut self, name: &'static str, help: &str, labels: &[(&str, &str)], v: f64) {
        self.metric(name, "gauge", help, labels, v);
    }
}

fn secs(ms: i64) -> f64 {
    ms as f64 / 1000.0
}

/// Токен сверяется по хэшам: время сравнения не зависит от совпавшего префикса.
fn authorized(st: &AppState, req: &Request) -> ApiResult<()> {
    let Some(want) = st.config.metrics_token.as_deref() else {
        return Err(ApiError::not_found("no_route"));
    };
    let got = bearer(req.headers()).unwrap_or_default();
    let (a, b) = (Hash::of(want.trim().as_bytes()), Hash::of(got.as_bytes()));
    if bool::from(a.0.ct_eq(&b.0)) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

pub async fn metrics(State(st): State<AppState>, req: Request) -> ApiResult<Response> {
    authorized(&st, &req)?;
    let mut o = Out::default();
    o.gauge(
        "selfsync_build_info",
        "Server and protocol version.",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("proto", &selfsync_proto::proto_header()),
        ],
        1.0,
    );
    o.gauge(
        "selfsync_process_start_time_seconds",
        "Process start time (socket-activated servers exit when idle).",
        &[],
        secs(st.started_ms),
    );

    let now = crate::db::now_ms();
    let (devices, events, blocked) = st
        .server_db(move |c| Ok((list_devices(c, None)?, counters(c)?, blocked_now(c, now)?)))
        .await?;
    for d in devices.iter().filter(|d| !d.revoked) {
        let id = d.id.to_string();
        let client = if d.client.is_empty() {
            "unknown"
        } else {
            d.client.as_str()
        };
        o.gauge(
            "selfsync_device_last_seen_timestamp_seconds",
            "Last device contact time (0 means never).",
            &[
                ("vault", &d.vault),
                ("device", &d.name),
                ("id", &id),
                ("client", client),
                ("read_only", if d.read_only { "true" } else { "false" }),
            ],
            secs(d.last_seen),
        );
    }
    for (rule, n) in &blocked {
        o.gauge(
            "selfsync_rate_limit_blocked",
            "Currently blocked rate-limit keys.",
            &[("rule", rule)],
            *n as f64,
        );
    }
    for (name, n) in &events {
        o.metric(
            "selfsync_events_total",
            "counter",
            "Events since server.db was created: 401, 403, 426, 429 and 5xx responses.",
            &[("event", name)],
            *n as f64,
        );
    }

    for name in list_vault_dirs(&st.config) {
        let v = st.vault(&name)?;
        let cfg = st.config.clone();
        let (s, vs, verify, devices_limit) = v
            .db(move |c, v| {
                let mut s = stats(c)?;
                let (bytes, n) = v.blobs.total_size()?;
                s.stored_bytes = bytes;
                s.blobs = n;
                let verify = [
                    "verify_at",
                    "verify_corrupt",
                    "verify_missing",
                    "verify_db_errors",
                    "verify_key_problem",
                ]
                .map(|k| meta_int(c, k));
                let verify = verify.into_iter().collect::<Result<Vec<_>, _>>()?;
                let mut vs = vault_state(c)?;
                crate::quota::fill_state(c, &cfg, &mut vs)?;
                let devices = crate::quota::limits(c, &cfg.quota.defaults)?.devices;
                Ok((s, vs, verify, devices))
            })
            .await?;
        let l = [("vault", name.as_str())];
        let n = |x: u64| x as f64;
        o.gauge("selfsync_vault_files", "Live files.", &l, n(s.files));
        o.gauge(
            "selfsync_vault_folders",
            "Live directories.",
            &l,
            n(s.folders),
        );
        o.gauge(
            "selfsync_vault_deleted",
            "Deleted paths in trash.",
            &l,
            n(s.deleted),
        );
        o.gauge(
            "selfsync_vault_revisions",
            "Historical revisions.",
            &l,
            n(s.revisions),
        );
        o.gauge(
            "selfsync_vault_live_bytes",
            "Total size of current revisions.",
            &l,
            n(s.live_bytes),
        );
        o.gauge(
            "selfsync_vault_stored_bytes",
            "Blob directory size.",
            &l,
            n(s.stored_bytes),
        );
        o.gauge("selfsync_vault_blobs", "Stored blobs.", &l, n(s.blobs));
        o.gauge("selfsync_vault_seq", "Change journal head.", &l, n(s.seq));
        o.gauge(
            "selfsync_vault_encrypted",
            "Vault is encrypted (key record exists).",
            &l,
            f64::from(u8::from(vs.key_version > 0)),
        );
        for (metric, help, x) in [
            (
                "selfsync_vault_quota_soft_bytes",
                "Quota: soft storage limit in bytes.",
                vs.quota_soft,
            ),
            (
                "selfsync_vault_quota_hard_bytes",
                "Quota: hard storage limit in bytes.",
                vs.quota_hard,
            ),
            (
                "selfsync_vault_devices_limit",
                "Quota: active devices.",
                u64::from(devices_limit),
            ),
        ] {
            if x > 0 {
                o.gauge(metric, help, &l, n(x));
            }
        }
        o.gauge(
            "selfsync_vault_blobs_wanted",
            "Blobs requested from devices after verification.",
            &l,
            f64::from(vs.blobs_wanted),
        );
        if let Some(at) = verify[0] {
            o.gauge(
                "selfsync_verify_last_run_timestamp_seconds",
                "Time of last selfsync verify.",
                &l,
                secs(at),
            );
            for (i, (metric, help)) in [
                (
                    "selfsync_verify_corrupt_blobs",
                    "Damaged blobs at last verification.",
                ),
                (
                    "selfsync_verify_missing_blobs",
                    "Missing blobs at last verification.",
                ),
                (
                    "selfsync_verify_db_errors",
                    "Vault database errors at last verification.",
                ),
                (
                    "selfsync_verify_key_problem",
                    "Key record is missing or invalid.",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                o.gauge(metric, help, &l, verify[i + 1].unwrap_or(0) as f64);
            }
        }
    }

    let mut r = o.text.into_response();
    *r.status_mut() = StatusCode::OK;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    Ok(r)
}
