mod capture;
mod dpi;
mod guard;
mod lease;
mod server;
mod uia;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "kuroko",
    about = "Elevated Windows desktop automation over MCP"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List top-level windows as JSON.
    Windows,
    /// Time repeated window enumerations.
    Bench {
        #[arg(short, long, default_value_t = 5)]
        runs: u32,
    },
    /// Run as an MCP server.
    Serve {
        /// stdio | http
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8900)]
        port: u16,
        /// Bearer token required on every HTTP request. Refuses to bind a
        /// non-loopback address without one.
        #[arg(long, env = "KUROKO_AUTH_KEY")]
        auth_key: Option<String>,
        /// Comma-separated client IPs permitted to connect.
        #[arg(long)]
        ip_allowlist: Option<String>,
    },
    /// List displays with their bounds and real scale factors.
    Displays,
    /// Capture the screen: full image, or only what changed since last time.
    Observe {
        /// text | image | diff
        #[arg(long, default_value = "image")]
        detail: String,
        /// Downscale to this width before encoding. 0 disables.
        #[arg(long, default_value_t = 1400)]
        max_width: u32,
        /// Write the PNG here.
        #[arg(long)]
        out: Option<String>,
        /// Observe this many times in ONE process. Diff needs a live process to
        /// hold the previous frame, so a single CLI shot can never exercise it.
        #[arg(long, default_value_t = 1)]
        watch: u32,
        #[arg(long, default_value_t = 2000)]
        interval_ms: u64,
    },
    /// Act on an element found by a previous discover.
    Act {
        #[arg(long)]
        scope: String,
        /// Comma-separated child-index path, e.g. "1,0,0,0,1".
        #[arg(long)]
        path: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        value: Option<String>,
    },
    /// Enumerate actionable elements in a window, each with a signed lease.
    Discover {
        /// Target window handle. Defaults to the foreground window.
        #[arg(long)]
        hwnd: Option<isize>,
        #[arg(long, default_value_t = 24)]
        max_depth: u32,
        #[arg(long, default_value_t = 400)]
        max_elements: usize,
        #[arg(long, default_value_t = 60)]
        ttl: u64,
        /// actionable (default) or all.
        #[arg(long, default_value = "actionable")]
        filter: uia::Filter,
        /// Include full bounds rects.
        #[arg(long)]
        verbose: bool,
        /// Print only the summary, not every entity.
        #[arg(long)]
        summary: bool,
        #[arg(long, default_value_t = 1)]
        runs: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kuroko=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Before any UIA query, any capture, any window handle. A process that has
    // not declared awareness is lied to by Windows: bounding rectangles and
    // screen captures come back in a virtualised coordinate space that does not
    // match where anything actually is. Every number kuroko returns is a
    // coordinate, so this has to happen first.
    dpi::declare_awareness();

    let cli = Cli::parse();
    let t0 = Instant::now();
    let lease_key = lease::new_key()?;
    let engine = uia::Engine::spawn(uia::EngineConfig { lease_key })?;
    let startup = t0.elapsed();
    tracing::info!(
        "UIA engine ready in {:.1}ms",
        startup.as_secs_f64() * 1000.0
    );

    match cli.cmd {
        Command::Windows => {
            let w = engine.list_windows().await?;
            println!("{}", serde_json::to_string_pretty(&w)?);
        }
        Command::Bench { runs } => {
            anyhow::ensure!(runs >= 1, "--runs must be at least 1");
            let mut ms = Vec::new();
            let mut count = 0usize;
            for _ in 0..runs {
                let t = Instant::now();
                let w = engine.list_windows().await?;
                ms.push(t.elapsed().as_secs_f64() * 1000.0);
                count = w.len();
            }
            ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!("windows        : {count}");
            println!("startup        : {:.1} ms", startup.as_secs_f64() * 1000.0);
            println!(
                "list_windows   : min {:.1} ms  med {:.1} ms  max {:.1} ms  (n={})",
                ms[0],
                ms[ms.len() / 2],
                ms[ms.len() - 1],
                runs
            );
        }
        Command::Serve {
            transport,
            host,
            port,
            auth_key,
            ip_allowlist,
        } => {
            guard::spawn_watcher();
            let allow: Vec<String> = ip_allowlist
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            server::serve(engine, &transport, &host, port, auth_key, allow).await?;
        }
        Command::Displays => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "process_dpi_awareness": dpi::awareness(),
                    "displays": dpi::displays()?,
                }))?
            );
        }
        Command::Observe {
            detail,
            max_width,
            out,
            watch,
            interval_ms,
        } => match detail.as_str() {
            "text" => {
                let wins = engine.list_windows().await?;
                let d = engine
                    .discover(uia::DiscoverArgs {
                        hwnd: None,
                        max_depth: 24,
                        max_elements: 400,
                        ttl_secs: 60,
                        filter: uia::Filter::Actionable,
                        verbose: false,
                    })
                    .await
                    .ok();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "windows": wins.iter().map(|w| serde_json::json!({
                            "name": w.name, "hwnd": w.hwnd, "pid": w.pid })).collect::<Vec<_>>(),
                        "focused": d,
                    }))?
                );
            }
            "image" | "diff" => {
                let is_diff = detail == "diff";
                for i in 0..watch.max(1) {
                    if i > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                    }
                    let out = out.clone();
                    let o = tokio::task::spawn_blocking(move || {
                        capture::observe(is_diff, max_width, out.as_deref())
                    })
                    .await??;
                    println!("{}", serde_json::to_string(&o)?);
                }
            }
            other => anyhow::bail!("unknown detail '{other}' (text|image|diff)"),
        },
        Command::Act {
            scope,
            path,
            action,
            value,
        } => {
            let path: Vec<u32> = path
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().parse())
                .collect::<std::result::Result<_, _>>()?;
            let r = engine
                .act(uia::ActArgs {
                    scope,
                    path,
                    action,
                    value,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Command::Discover {
            hwnd,
            max_depth,
            max_elements,
            ttl,
            filter,
            verbose,
            summary,
            runs,
        } => {
            anyhow::ensure!(runs >= 1, "--runs must be at least 1");
            let mut ms = Vec::new();
            let mut last = None;
            for _ in 0..runs {
                let d = engine
                    .discover(uia::DiscoverArgs {
                        hwnd,
                        max_depth,
                        max_elements,
                        ttl_secs: ttl,
                        filter,
                        verbose,
                    })
                    .await?;
                ms.push(d.elapsed_ms);
                last = Some(d);
            }
            let d = last.expect("at least one run");
            ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            if summary {
                println!("window     : {} [{}]", d.window.name, d.window.control_type);
                println!("hwnd/pid   : {} / {}", d.window.hwnd, d.window.pid);
                println!("generation : {}", d.generation);
                println!("entities   : {}", d.entities.len());
                if let Some(t) = &d.truncated {
                    println!("TRUNCATED  : {t}");
                }
                println!(
                    "discover   : min {:.1} ms  med {:.1} ms  max {:.1} ms  (n={})",
                    ms[0],
                    ms[ms.len() / 2],
                    ms[ms.len() - 1],
                    runs
                );
                let json = serde_json::to_string(&d)?;
                println!("json bytes : {}  (~{} tokens)", json.len(), json.len() / 4);
            } else {
                println!("{}", serde_json::to_string_pretty(&d)?);
            }
        }
    }
    Ok(())
}
