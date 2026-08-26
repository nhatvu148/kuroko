//! The MCP surface.
//!
//! Five tools, and deliberately no sixth. This process runs at High integrity
//! and is reachable over the network, so every tool is attack surface: there is
//! no shell, no registry, no filesystem, no arbitrary process spawn. Anything
//! outside "look at the desktop and act on a control" belongs on the SSH side,
//! where it is not running with an admin token.

use crate::{capture, guard, uia};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Clone)]
pub struct Kuroko {
    engine: uia::Engine,
    allowlist: std::sync::Arc<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct DiscoverParams {
    /// Window handle from `windows`. Omit to use the foreground window.
    pub hwnd: Option<isize>,
    /// "actionable" (default) or "all".
    pub filter: Option<String>,
    /// Cap on returned entities. Default 400.
    pub max_elements: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActParams {
    /// The `scope` string from the discover response that produced this entity.
    pub scope: String,
    /// The entity's `path`.
    pub path: Vec<u32>,
    /// click | type | toggle | expand | select
    pub action: String,
    /// Text, for `type`.
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ObserveParams {
    /// "text" (window list + focused elements), "image" (full screen),
    /// or "diff" (only what changed since the last observe).
    pub detail: Option<String>,
    /// Downscale width before encoding. Default 1400; 0 for native.
    pub max_width: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LaunchParams {
    /// Must appear in the launch allowlist.
    pub name: String,
}

#[tool_router]
impl Kuroko {
    /// The allowlist is loaded once by the caller and shared. Loading it here
    /// would re-read the file and repeat a security-relevant syscall
    /// (`SetSecurityInfo`) on every new HTTP session.
    pub fn new(engine: uia::Engine, allowlist: std::sync::Arc<Vec<String>>) -> Self {
        Self { engine, allowlist }
    }

    #[tool(
        name = "windows",
        description = "List top-level windows with their handles, pids and bounds."
    )]
    async fn windows(&self) -> Result<Json<serde_json::Value>, McpError> {
        let w = self
            .engine
            .list_windows()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(Json(serde_json::json!({ "windows": w })))
    }

    #[tool(
        name = "discover",
        description = "List the actionable elements of a window. Returns a signed `scope` plus \
                       entities each carrying a `path`; pass both to `act`. Always discover before acting."
    )]
    async fn discover(
        &self,
        Parameters(p): Parameters<DiscoverParams>,
    ) -> Result<Json<uia::Discovery>, McpError> {
        let filter = match p.filter.as_deref().unwrap_or("actionable") {
            "all" => uia::Filter::All,
            _ => uia::Filter::Actionable,
        };
        self.engine
            .discover(uia::DiscoverArgs {
                hwnd: p.hwnd,
                max_depth: 24,
                max_elements: p.max_elements.unwrap_or(400),
                ttl_secs: crate::lease::DEFAULT_TTL_SECS,
                filter,
                verbose: false,
            })
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    #[tool(
        name = "act",
        description = "Act on one element via its UIA control pattern. Verifies the window is \
                       unchanged and the element is still present and enabled before doing anything; \
                       a non-ok `status` means nothing was done and you should discover again."
    )]
    async fn act(
        &self,
        Parameters(p): Parameters<ActParams>,
    ) -> Result<Json<uia::ActResult>, McpError> {
        if guard::engaged() {
            return Err(McpError::internal_error(guard::refusal(), None));
        }
        self.engine
            .act(uia::ActArgs {
                scope: p.scope,
                path: p.path,
                action: p.action,
                value: p.value,
            })
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    #[tool(
        name = "observe",
        description = "See the screen. `diff` is much cheaper than `image` during a wait - it \
                       returns nothing at all when the screen has not changed."
    )]
    async fn observe(
        &self,
        Parameters(p): Parameters<ObserveParams>,
    ) -> Result<CallToolResult, McpError> {
        let detail = p.detail.unwrap_or_else(|| "image".into());
        if detail == "text" {
            let wins = self
                .engine
                .list_windows()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            let focused = self
                .engine
                .discover(uia::DiscoverArgs {
                    hwnd: None,
                    max_depth: 24,
                    max_elements: 400,
                    ttl_secs: crate::lease::DEFAULT_TTL_SECS,
                    filter: uia::Filter::Actionable,
                    verbose: false,
                })
                .await
                .ok();
            let v = serde_json::json!({ "windows": wins, "focused": focused });
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                v.to_string(),
            )]));
        }

        let is_diff = detail == "diff";
        let max_width = p.max_width.unwrap_or(1400);
        let (obs, png) =
            tokio::task::spawn_blocking(move || capture::observe_bytes(is_diff, max_width))
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let meta = serde_json::to_string(&obs).unwrap_or_default();
        let mut out = vec![ContentBlock::text(meta)];
        // No bytes when nothing changed, or when the region hull was judged
        // unrepresentative - the metadata already says what happened.
        if !png.is_empty() {
            use base64::{engine::general_purpose::STANDARD as B64S, Engine};
            out.push(ContentBlock::image(
                B64S.encode(&png),
                "image/png".to_string(),
            ));
        }
        Ok(CallToolResult::success(out))
    }

    #[tool(
        name = "launch",
        description = "Start an application. Only names present in the server's launch allowlist \
                       are permitted; there is no way to run an arbitrary command."
    )]
    async fn launch(
        &self,
        Parameters(p): Parameters<LaunchParams>,
    ) -> Result<Json<serde_json::Value>, McpError> {
        if guard::engaged() {
            return Err(McpError::internal_error(guard::refusal(), None));
        }
        let want = p.name.trim().to_lowercase();
        if !self.allowlist.contains(&want) {
            return Err(McpError::invalid_params(
                format!(
                    "'{}' is not in the launch allowlist ({} entries). Add it to \
                     %LOCALAPPDATA%\\kuroko\\launch-allowlist.txt on the host.",
                    p.name,
                    self.allowlist.len()
                ),
                None,
            ));
        }
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &p.name])
            .spawn()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(Json(serde_json::json!({ "launched": p.name })))
    }
}

#[tool_handler]
impl ServerHandler for Kuroko {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo and Implementation are #[non_exhaustive]: build from
        // Default and assign, rather than a struct literal.
        let mut me = Implementation::default();
        me.name = "kuroko".into();
        me.version = env!("CARGO_PKG_VERSION").into();

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = me;
        // Rules ride the handshake rather than an instructions file, so a
        // client that never reads project docs still inherits them.
        info.instructions = Some(
            "Windows desktop automation.\n\
             - ALWAYS `discover` before `act`. Pass back the response's `scope` together with \
               the entity's `path`; never invent either.\n\
             - A `status` other than \"ok\" means NOTHING happened. `identity_changed` or \
               `not_found` means the window moved on - discover again rather than retrying.\n\
             - Prefer `observe` detail=\"diff\" while waiting for something to happen; it costs \
               nothing when the screen is static. Use detail=\"image\" only when you need to see \
               an app that exposes no UI tree.\n\
             - Scopes expire after 60s.\n\
             - There is no shell here. For files, processes and commands, use SSH instead."
                .into(),
        );
        info
    }
}

/// Bring the server up on stdio (local Claude Code) or streamable HTTP (remote
/// over Tailscale).
pub async fn serve(
    engine: uia::Engine,
    transport: &str,
    host: &str,
    port: u16,
    auth_key: Option<String>,
    ip_allowlist: Vec<String>,
) -> anyhow::Result<()> {
    match transport {
        "stdio" => {
            use rmcp::ServiceExt;
            let allowlist = std::sync::Arc::new(guard::load_allowlist());
            let service = Kuroko::new(engine, allowlist)
                .serve(rmcp::transport::stdio())
                .await?;
            service.waiting().await?;
            Ok(())
        }
        "http" => {
            // Decided on the resolved address, not the spelling: "localhost"
            // can resolve to a non-loopback address on a badly configured host.
            let loopback = tokio::net::lookup_host((host, port))
                .await
                .map(|mut a| a.all(|s| s.ip().is_loopback()))
                .unwrap_or(false);
            // Refusing rather than warning: this process holds an admin token,
            // and an unauthenticated bind is not a mistake worth allowing a flag
            // to override.
            if !loopback && auth_key.is_none() {
                anyhow::bail!(
                    "refusing to bind {host} without --auth-key: this server runs elevated"
                );
            }
            serve_http(engine, host, port, auth_key, ip_allowlist).await
        }
        other => anyhow::bail!("unknown transport '{other}' (stdio|http)"),
    }
}

async fn serve_http(
    engine: uia::Engine,
    host: &str,
    port: u16,
    auth_key: Option<String>,
    ip_allowlist: Vec<String>,
) -> anyhow::Result<()> {
    use axum::extract::ConnectInfo;
    use axum::http::StatusCode;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::StreamableHttpService;
    use std::net::SocketAddr;

    let allowlist = std::sync::Arc::new(guard::load_allowlist());
    let svc = StreamableHttpService::new(
        move || Ok(Kuroko::new(engine.clone(), allowlist.clone())),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let key = auth_key.clone();
    let allow_count = ip_allowlist.len();
    let allow = std::sync::Arc::new(ip_allowlist);

    let app = axum::Router::new()
        .nest_service("/mcp", svc)
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let key = key.clone();
                let allow = allow.clone();
                async move {
                    // Peer address first: an unauthorised source should not even get
                    // to present a token, and a wrong token should not reveal
                    // whether the address would have been accepted.
                    if !allow.is_empty() {
                        let ip = req
                            .extensions()
                            .get::<ConnectInfo<SocketAddr>>()
                            .map(|c| c.0.ip().to_string())
                            .unwrap_or_default();
                        if !allow.contains(&ip) {
                            tracing::warn!("rejected connection from {ip}");
                            return Err(StatusCode::FORBIDDEN);
                        }
                    }
                    if let Some(k) = key.as_ref() {
                        let ok = req
                            .headers()
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "))
                            .map(|t| constant_time_eq(t.as_bytes(), k.as_bytes()))
                            .unwrap_or(false);
                        if !ok {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                    Ok(next.run(req).await)
                }
            },
        ));

    // `SocketAddr::from_str` neither resolves names nor tolerates an unbracketed
    // IPv6 literal, so the loopback check above accepted "localhost" and "::1"
    // as valid while binding them failed. Resolve instead of parsing.
    let addr: SocketAddr = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("cannot resolve {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("{host}:{port} resolved to no addresses"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "kuroko listening on http://{addr}/mcp  (auth: {}, ip allowlist entries: {})",
        if auth_key.is_some() { "on" } else { "OFF" },
        allow_count
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Comparison that does not leak the correct prefix length through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
