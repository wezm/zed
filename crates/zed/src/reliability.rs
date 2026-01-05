use anyhow::{Context as _, Result};
use client::{TelemetrySettings, telemetry::MINIDUMP_ENDPOINT};
use futures::AsyncReadExt;
use gpui::{App, AppContext as _};
use http_client::{self, HttpClient, HttpClientWithUrl};
use project::Project;
use proto::{CrashReport, GetCrashFilesResponse};
use reqwest::multipart::{Form, Part};
use settings::Settings;
use smol::stream::StreamExt;
use std::{ffi::OsStr, fs, sync::Arc};
use util::ResultExt;

#[cfg(target_os = "macos")]
pub fn monitor_main_thread_hangs(
    http_client: Arc<HttpClientWithUrl>,
    installation_id: Option<String>,
    cx: &App,
) {
    // This is too noisy to ship to stable for now.
    if !matches!(
        ReleaseChannel::global(cx),
        ReleaseChannel::Dev | ReleaseChannel::Nightly | ReleaseChannel::Preview
    ) {
        return;
    }

    use nix::sys::signal::{
        SaFlags, SigAction, SigHandler, SigSet,
        Signal::{self, SIGUSR2},
        sigaction,
    };

    use parking_lot::Mutex;

    use http_client::Method;
    use release_channel::ReleaseChannel;
    use std::{
        ffi::c_int,
        sync::{OnceLock, mpsc},
        time::Duration,
    };
    use telemetry_events::{BacktraceFrame, HangReport};

    use nix::sys::pthread;

    let foreground_executor = cx.foreground_executor();
    let background_executor = cx.background_executor();
    let telemetry_settings = *client::TelemetrySettings::get_global(cx);

    // Initialize SIGUSR2 handler to send a backtrace to a channel.
    let (backtrace_tx, backtrace_rx) = mpsc::channel();
    static BACKTRACE: Mutex<Vec<backtrace::Frame>> = Mutex::new(Vec::new());
    static BACKTRACE_SENDER: OnceLock<mpsc::Sender<()>> = OnceLock::new();
    BACKTRACE_SENDER.get_or_init(|| backtrace_tx);
    BACKTRACE.lock().reserve(100);

    fn handle_backtrace_signal() {
        unsafe {
            extern "C" fn handle_sigusr2(_i: c_int) {
                unsafe {
                    // ASYNC SIGNAL SAFETY: This lock is only accessed one other time,
                    // which can only be triggered by This signal handler. In addition,
                    // this signal handler is immediately removed by SA_RESETHAND, and this
                    // signal handler cannot be re-entrant due to the SIGUSR2 mask defined
                    // below
                    let mut bt = BACKTRACE.lock();
                    bt.clear();
                    backtrace::trace_unsynchronized(|frame| {
                        if bt.len() < bt.capacity() {
                            bt.push(frame.clone());
                            true
                        } else {
                            false
                        }
                    });
                }

                BACKTRACE_SENDER.get().unwrap().send(()).ok();
            }

            let mut mask = SigSet::empty();
            mask.add(SIGUSR2);
            sigaction(
                Signal::SIGUSR2,
                &SigAction::new(
                    SigHandler::Handler(handle_sigusr2),
                    SaFlags::SA_RESTART | SaFlags::SA_RESETHAND,
                    mask,
                ),
            )
            .log_err();
        }
    }

    handle_backtrace_signal();
    let main_thread = pthread::pthread_self();

    let (mut tx, mut rx) = futures::channel::mpsc::channel(3);
    foreground_executor
        .spawn(async move { while (rx.next().await).is_some() {} })
        .detach();

    background_executor
        .spawn({
            let background_executor = background_executor.clone();
            async move {
                loop {
                    background_executor.timer(Duration::from_secs(1)).await;
                    match tx.try_send(()) {
                        Ok(_) => continue,
                        Err(e) => {
                            if e.into_send_error().is_full() {
                                pthread::pthread_kill(main_thread, SIGUSR2).log_err();
                            }
                            // Only detect the first hang
                            break;
                        }
                    }
                }
            }
        })
        .detach();

    let app_version = release_channel::AppVersion::global(cx);
    let os_name = client::telemetry::os_name();

    background_executor
        .clone()
        .spawn(async move {
            let os_version = client::telemetry::os_version();

            loop {
                while backtrace_rx.recv().is_ok() {
                    if !telemetry_settings.diagnostics {
                        return;
                    }

                    // ASYNC SIGNAL SAFETY: This lock is only accessed _after_
                    // the backtrace transmitter has fired, which itself is only done
                    // by the signal handler. And due to SA_RESETHAND  the signal handler
                    // will not run again until `handle_backtrace_signal` is called.
                    let raw_backtrace = BACKTRACE.lock().drain(..).collect::<Vec<_>>();
                    let backtrace: Vec<_> = raw_backtrace
                        .into_iter()
                        .map(|frame| {
                            let mut btf = BacktraceFrame {
                                ip: frame.ip() as usize,
                                symbol_addr: frame.symbol_address() as usize,
                                base: frame.module_base_address().map(|addr| addr as usize),
                                symbols: vec![],
                            };

                            backtrace::resolve_frame(&frame, |symbol| {
                                if let Some(name) = symbol.name() {
                                    btf.symbols.push(name.to_string());
                                }
                            });

                            btf
                        })
                        .collect();

                    // IMPORTANT: Don't move this to before `BACKTRACE.lock()`
                    handle_backtrace_signal();

                    log::error!(
                        "Suspected hang on main thread:\n{}",
                        backtrace
                            .iter()
                            .flat_map(|bt| bt.symbols.first().as_ref().map(|s| s.as_str()))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );

                    let report = HangReport {
                        backtrace,
                        app_version: Some(app_version),
                        os_name: os_name.clone(),
                        os_version: Some(os_version.clone()),
                        architecture: std::env::consts::ARCH.into(),
                        installation_id: installation_id.clone(),
                    };

                    let Some(json_bytes) = serde_json::to_vec(&report).log_err() else {
                        continue;
                    };

                    let Some(checksum) = client::telemetry::calculate_json_checksum(&json_bytes)
                    else {
                        continue;
                    };

                    let Ok(url) = http_client.build_zed_api_url("/telemetry/hangs", &[]) else {
                        continue;
                    };

                    let Ok(request) = http_client::Request::builder()
                        .method(Method::POST)
                        .uri(url.as_ref())
                        .header("x-zed-checksum", checksum)
                        .body(json_bytes.into())
                    else {
                        continue;
                    };

                    if let Some(response) = http_client.send(request).await.log_err()
                        && response.status() != 200
                    {
                        log::error!("Failed to send hang report: HTTP {:?}", response.status());
                    }
                }
            }
        })
        .detach()
}

trait FormExt {
    fn text_if_some(
        self,
        label: impl Into<std::borrow::Cow<'static, str>>,
        value: Option<impl Into<std::borrow::Cow<'static, str>>>,
    ) -> Self;
}

impl FormExt for Form {
    fn text_if_some(
        self,
        label: impl Into<std::borrow::Cow<'static, str>>,
        value: Option<impl Into<std::borrow::Cow<'static, str>>>,
    ) -> Self {
        match value {
            Some(value) => self.text(label.into(), value.into()),
            None => self,
        }
    }
}
