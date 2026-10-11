//! The captive portal's web page, served with axum on the hotspot's gateway only. Each submitted
//! form is handed to the engine, which owns the coupons; this server only speaks HTTP.
//!
//! Every device on the open network can reach it: connections are capped (globally and per
//! device), headers must arrive within a few seconds, a whole connection is time-boxed, bodies
//! are size-limited, and everything echoed back is HTML-escaped.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use tokio::sync::{oneshot, Semaphore};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::error::Result;
use crate::constants::PORTAL_HOSTNAME;
use crate::models::COUNTRY_CODES;
use crate::models::TimeMode;
use crate::portal_store::{Access, SignIn};

const MAX_BODY: usize = 4 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_PER_DEVICE: usize = 4;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// A connection that is still open after this is dropped, whatever it is doing.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);

/// A sign-in for the engine to check. `reply` gets the seconds of access left, or a message
/// for the person at the device.
pub struct PortalRequest {
    /// `None`: the device only asks how much time it has left.
    pub form: Option<SignIn>,
    pub ip: String,
    pub reply: oneshot::Sender<std::result::Result<Access, String>>,
}

#[derive(Clone)]
pub struct PageInfo {
    pub ssid: String,
    pub country_code: String,
}

/// Runs on its own thread with its own tokio runtime; stops when dropped.
pub struct PortalServer {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct Shared {
    page: PageInfo,
    home: String,
    /// Port 80 of the gateway leads here for every device, signed in or not.
    status_url: String,
    requests: Sender<PortalRequest>,
}

impl PortalServer {
    /// Listens on `addr`, or on a free port of the same address if that port is taken.
    pub fn start(addr: SocketAddr, page: PageInfo, requests: Sender<PortalRequest>) -> Result<Self> {
        let listener = match std::net::TcpListener::bind(addr) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => std::net::TcpListener::bind((addr.ip(), 0))?,
            other => other?,
        };
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let shared = Shared {
            page,
            home: format!("http://{}:{port}/", addr.ip()),
            status_url: format!("http://{PORTAL_HOSTNAME}/"),
            requests,
        };
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (shutdown, stop) = oneshot::channel();
        let thread = thread::spawn(move || runtime.block_on(serve(listener, shared, stop)));
        Ok(Self { port, shutdown: Some(shutdown), thread: Some(thread) })
    }

    /// The port actually used: the firewall redirect must point there.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PortalServer {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

async fn serve(listener: std::net::TcpListener, shared: Shared, mut stop: oneshot::Receiver<()>) {
    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else { return };
    let app = Router::new()
        .route("/", get(form))
        .route("/login", post(login))
        .route("/icon.svg", get(icon))
        // every other URL, including the OS connectivity checks, leads to the form
        .fallback(redirect)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .with_state(shared);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_device: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut stop => return,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(_) => continue,
            },
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue }; // full: dropped
        {
            let mut open = per_device.lock().unwrap();
            let count = open.entry(peer.ip()).or_default();
            if *count >= MAX_PER_DEVICE {
                continue;
            }
            *count += 1;
        }
        let service = TowerToHyperService::new(app.clone().layer(Extension(peer)));
        let per_device = per_device.clone();
        tokio::spawn(async move {
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection).await;
            let mut open = per_device.lock().unwrap();
            if let Some(count) = open.get_mut(&peer.ip()) {
                *count -= 1;
                if *count == 0 {
                    open.remove(&peer.ip());
                }
            }
            drop(slot);
        });
    }
}

async fn ask_engine(shared: &Shared, form: Option<SignIn>, peer: SocketAddr) -> std::result::Result<Access, String> {
    let (reply, answer) = oneshot::channel();
    let request = PortalRequest { form, ip: peer.ip().to_string(), reply };
    match shared.requests.send(request) {
        Ok(()) => match tokio::time::timeout(ENGINE_TIMEOUT, answer).await {
            Ok(Ok(result)) => result,
            _ => Err("The hotspot is busy, try again.".into()),
        },
        Err(_) => Err("The hotspot is stopping.".into()),
    }
}

/// Signed-in devices see their time left, the others the sign-in form.
async fn form(State(shared): State<Shared>, Extension(peer): Extension<SocketAddr>) -> Html<String> {
    Html(match ask_engine(&shared, None, peer).await {
        Ok(access) if access.left_secs > 0 => status_page(&shared.page, access, &shared.status_url),
        _ => form_page(&shared.page, &Fields::default(), None),
    })
}

async fn login(State(shared): State<Shared>, Extension(peer): Extension<SocketAddr>, Form(fields): Form<Fields>) -> Html<String> {
    Html(match ask_engine(&shared, Some(fields.sign_in()), peer).await {
        Ok(access) => done_page(&shared.page, access, &shared.status_url),
        Err(message) => form_page(&shared.page, &fields, Some(&message)),
    })
}

async fn icon() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], ICON).into_response()
}

async fn redirect(State(shared): State<Shared>) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, shared.home)]).into_response()
}

#[derive(Default, Debug, PartialEq, Deserialize)]
#[serde(default)]
struct Fields {
    first_name: String,
    last_name: String,
    country_code: String,
    phone: String,
    code: String,
}

impl Fields {
    fn sign_in(&self) -> SignIn {
        SignIn {
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            country_code: self.country_code.clone(),
            phone: self.phone.clone(),
            code: self.code.clone(),
        }
    }
}

fn escape(s: &str) -> String {
    s.chars().fold(String::with_capacity(s.len()), |mut out, c| {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
        out
    })
}

fn duration_label(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    let days = format!("{d} day{}", if d == 1 { "" } else { "s" });
    match (d, h, m) {
        (0, 0, _) => format!("{} min", m.max(1)),
        (0, _, 0) => format!("{h} h"),
        (0, _, _) => format!("{h} h {m} min"),
        (_, 0, _) => days,
        _ => format!("{days} {h} h"),
    }
}

/// The app's icon, so guests see whose network this is.
const ICON: &str = include_str!("../../../packaging/hotspot.svg");

const STYLE: &str = r#"
:root{--bg:#EEF2F4;--card:#fff;--text:#14191F;--muted:#5B6672;--line:#DCE2E7;--brand:#0F6B7C;--brand-soft:#E1F0F2;
--warn:#B45309;--warn-soft:#FDF0E1;--err:#A8261D;--err-soft:#FCE9E7;--input:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0E1215;--card:#171C21;--text:#E8ECEF;--muted:#98A3AE;--line:#2A3239;
--brand:#4FB3C4;--brand-soft:#16323A;--warn:#F0A44B;--warn-soft:#3A2A16;--err:#F2867C;--err-soft:#3A1D1A;--input:#0F1418}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--text);
background:radial-gradient(1200px 500px at 50% -200px,var(--brand-soft),var(--bg));padding:28px 16px 40px}
.wrap{max-width:420px;margin:0 auto}
.brand{display:flex;align-items:center;gap:12px;margin:0 4px 18px}
.brand img{width:44px;height:44px;border-radius:12px;box-shadow:0 4px 14px rgba(15,107,124,.25)}
.net{font-weight:700;font-size:18px}.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 10px 30px rgba(20,25,31,.06)}
h1{font-size:22px;margin:0 0 6px}p{color:var(--muted);margin:0 0 16px}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 6px}
input,select{width:100%;font:inherit;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:var(--input);color:var(--text)}
input:focus,select:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:transparent}
.row{display:flex;gap:8px}.row select{flex:0 0 40%}.row input{flex:1}
#cc{font-family:ui-monospace,Menlo,monospace;letter-spacing:.12em;text-transform:uppercase}
button,.button{display:block;width:100%;margin-top:22px;font-family:inherit;font-size:16px;font-weight:600;line-height:1.2;padding:14px;border:0;border-radius:12px;
background:var(--brand);color:#fff;text-align:center;text-decoration:none;cursor:pointer}
.error{background:var(--err-soft);color:var(--err);border-radius:10px;padding:10px 12px;margin-bottom:6px;font-size:14px}
.center{text-align:center}
.ring{position:relative;width:220px;height:220px;margin:6px auto 14px}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.track{fill:none;stroke:var(--line);stroke-width:10}
.arc{fill:none;stroke:var(--brand);stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1s linear,stroke .3s}
.low .arc{stroke:var(--warn)}.low .big{color:var(--warn)}
.ring-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.big{font:700 32px/1.1 ui-monospace,Menlo,monospace;font-variant-numeric:tabular-nums}
.chips{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-bottom:14px}
.chip{background:var(--brand-soft);color:var(--brand);border-radius:999px;padding:5px 12px;font-size:13px;font-weight:600}
.ok{width:72px;height:72px;margin:4px auto 14px;border-radius:50%;background:var(--brand-soft);color:var(--brand);
display:flex;align-items:center;justify-content:center;font-size:38px;font-weight:700}
.foot{color:var(--muted);font-size:13px;text-align:center;margin-top:18px}
.foot a{color:var(--brand);font-weight:600}
"#;

fn shell(page: &PageInfo, title: &str, head: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\">\
<link rel=\"icon\" href=\"/icon.svg\"><title>{title}</title><style>{STYLE}</style>{head}</head><body><div class=\"wrap\">\
<header class=\"brand\"><img src=\"/icon.svg\" alt=\"\"><div><div class=\"net\">{ssid}</div><div class=\"sub\">Wi-Fi access</div></div></header>\
{body}</div></body></html>",
        ssid = escape(&page.ssid),
    )
}

fn form_page(page: &PageInfo, f: &Fields, error: Option<&str>) -> String {
    let selected = if f.country_code.is_empty() { page.country_code.as_str() } else { f.country_code.as_str() };
    let options: String = COUNTRY_CODES
        .iter()
        .map(|(name, code)| {
            let sel = if *code == selected { " selected" } else { "" };
            format!("<option value=\"{code}\"{sel}>{} ({code})</option>", escape(name))
        })
        .collect();
    let error = error.map(|e| format!("<div class=\"error\" role=\"alert\">{}</div>", escape(e))).unwrap_or_default();
    let body = format!(
        "<main class=\"card\"><h1>Get online</h1><p>Enter your details and the coupon code you were given.</p>{error}\
<form method=\"post\" action=\"/login\">\
<label for=\"fn\">First name</label><input id=\"fn\" name=\"first_name\" autocomplete=\"given-name\" maxlength=\"64\" required value=\"{first}\">\
<label for=\"ln\">Last name</label><input id=\"ln\" name=\"last_name\" autocomplete=\"family-name\" maxlength=\"64\" required value=\"{last}\">\
<label for=\"ph\">Phone number</label><div class=\"row\"><select name=\"country_code\" aria-label=\"Country code\">{options}</select>\
<input id=\"ph\" name=\"phone\" type=\"tel\" inputmode=\"tel\" autocomplete=\"tel-national\" maxlength=\"20\" required value=\"{phone}\"></div>\
<label for=\"cc\">Coupon code</label><input id=\"cc\" name=\"code\" autocapitalize=\"characters\" autocomplete=\"off\" maxlength=\"20\" placeholder=\"XXXX-XXXX\" required value=\"{code}\">\
<button type=\"submit\">Connect</button></form></main>\
<p class=\"foot\">Your name and phone number are deleted 30 days after your access ends.</p>",
        first = escape(&f.first_name),
        last = escape(&f.last_name),
        phone = escape(&f.phone),
        code = escape(&f.code),
    );
    shell(page, &escape(&page.ssid), "", &body)
}

fn done_page(page: &PageInfo, access: Access, status_url: &str) -> String {
    let body = format!(
        "<main class=\"card center\"><div class=\"ok\">✓</div><h1>You're online</h1>\
<p>You have {left} of internet on {ssid}.</p><a class=\"button\" href=\"/\">See my time left</a></main>\
<p class=\"foot\">Check your time anytime at <a href=\"{url}\">{url}</a></p>",
        ssid = escape(&page.ssid),
        left = duration_label(access.left_secs),
        url = escape(status_url),
    );
    shell(page, "You're online", "", &body)
}

/// `1:05:09`, or `2 d 01:05:09`: what the countdown shows before its script runs.
fn clock(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60, secs % 60);
    let time = format!("{h:02}:{m:02}:{s:02}");
    if d > 0 { format!("{d} d {time}") } else { time }
}

/// Counts down in the browser and reloads every minute: connected-time coupons pause while
/// the device is away, so only the engine knows the exact figure.
fn status_page(page: &PageInfo, access: Access, status_url: &str) -> String {
    let (left, total) = (access.left_secs, access.total_secs.max(1));
    let offset = 100 - (left.min(total) * 100 / total);
    let connected = access.time_mode == TimeMode::Connected;
    let mode = if connected { "Counts only while connected" } else { "Runs in real time" };
    let body = format!(
        "<main class=\"card center\" id=\"box\"><div class=\"ring\"><svg viewBox=\"0 0 120 120\" aria-hidden=\"true\">\
<circle class=\"track\" cx=\"60\" cy=\"60\" r=\"52\"/><circle class=\"arc\" id=\"arc\" cx=\"60\" cy=\"60\" r=\"52\" pathLength=\"100\" \
stroke-dasharray=\"100\" stroke-dashoffset=\"{offset}\"/></svg><div class=\"ring-text\"><div class=\"big\" id=\"left\">{start}</div>\
<p style=\"margin:4px 0 0\">left</p></div></div>\
<div class=\"chips\"><span class=\"chip\">{total_label} coupon</span><span class=\"chip\">{mode}</span></div>\
<p id=\"note\">{note}</p></main>\
<p class=\"foot\">Bookmark <a href=\"{url}\">{url}</a> to check again.</p>\
<script>let s={left};const T={total},C={connected},L=document.getElementById('left'),A=document.getElementById('arc'),\
B=document.getElementById('box'),N=document.getElementById('note'),p=n=>String(n).padStart(2,'0');\
function show(){{const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);\
L.textContent=s?(d?d+' d ':'')+p(h)+':'+p(m)+':'+p(s%60):\"Time's up\";A.style.strokeDashoffset=100-Math.min(s,T)*100/T;\
B.classList.toggle('low',s<300);\
if(!s)N.textContent='Ask for a new coupon to keep browsing.';\
else if(!C)N.textContent='Ends at '+new Date(Date.now()+s*1000).toLocaleString([],{{weekday:'short',hour:'2-digit',minute:'2-digit'}});}}\
show();setInterval(()=>{{if(s>0)s--;show();}},1000);</script>",
        start = clock(left),
        total_label = duration_label(access.total_secs),
        note = if connected { "Your time pauses when you leave the network." } else { "" },
        url = escape(status_url),
    );
    shell(page, "Time left", "<meta http-equiv=\"refresh\" content=\"60\">", &body)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::mpsc::channel;

    use super::*;

    fn page() -> PageInfo {
        PageInfo { ssid: "Cafe".into(), country_code: "+91".into() }
    }

    fn http(port: u16, request: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn echoed_values_are_escaped() {
        let page = PageInfo { ssid: "<Cafe>".into(), country_code: "+91".into() };
        let f = Fields { first_name: "\"><script>alert(1)</script>".into(), ..Fields::default() };
        let html = form_page(&page, &f, Some("<b>bad</b>"));
        assert!(!html.contains("<script>") && !html.contains("<b>bad</b>") && !html.contains("<Cafe>"));
        assert!(html.contains("<option value=\"+91\" selected>India (+91)</option>"));
    }

    #[test]
    fn serves_form_redirects_and_signs_in() {
        let (tx, rx) = channel::<PortalRequest>();
        let server = PortalServer::start("127.0.0.1:0".parse().unwrap(), page(), tx).unwrap();
        let port = server.port();

        let checked = http(port, "GET /generate_204 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(checked.starts_with("HTTP/1.1 302"), "{checked}");
        assert!(checked.to_lowercase().contains(&format!("location: http://127.0.0.1:{port}/")));
        let engine = thread::spawn(move || {
            // not signed in yet: the form
            rx.recv().unwrap().reply.send(Err("not signed in".into())).unwrap();
            let req = rx.recv().unwrap();
            let form = req.form.unwrap();
            assert_eq!((form.code.as_str(), form.last_name.as_str()), ("HX7K-29QM", "Rão K"));
            req.reply.send(Ok(Access { left_secs: 3600, total_secs: 3600, time_mode: TimeMode::Real })).unwrap();
            // signed in: the time left
            let req = rx.recv().unwrap();
            assert!(req.form.is_none());
            req.reply.send(Ok(Access { left_secs: 3000, total_secs: 3600, time_mode: TimeMode::Connected })).unwrap();
        });
        let html = http(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(html.contains("Coupon code") && html.to_lowercase().contains("cache-control: no-store"));
        let body = "first_name=A&last_name=R%C3%A3o+K&country_code=%2B91&phone=9876543210&code=HX7K-29QM";
        let post = format!(
            "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(http(port, &post).contains("You're online"));
        let status = http(port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(status.contains("Time left") && status.contains("let s=3000;") && status.contains("00:50:00"));
        assert!(http(port, "GET /icon.svg HTTP/1.1\r\nHost: x\r\n\r\n").contains("image/svg+xml"));
        engine.join().unwrap();
    }

    #[test]
    fn oversized_body_is_refused() {
        let (tx, _rx) = channel::<PortalRequest>();
        let server = PortalServer::start("127.0.0.1:0".parse().unwrap(), page(), tx).unwrap();
        let body = "code=".to_string() + &"A".repeat(MAX_BODY * 2);
        let post = format!(
            "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(http(server.port(), &post).starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn falls_back_to_a_free_port() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (tx, _rx) = channel::<PortalRequest>();
        let server = PortalServer::start(taken.local_addr().unwrap(), page(), tx).unwrap();
        assert_ne!(server.port(), taken.local_addr().unwrap().port());
    }
}
