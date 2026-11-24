//! 最小 HTTP 服务(std-only):静态页、/api/stats、POST /api/inject、/ws 升级。

use crate::{ws, ClientHandle, Filter, HttpState, CLIENT_SEQ};
use serde_json::json;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub content_length: usize,
}

fn read_request(rdr: &mut BufReader<TcpStream>) -> Result<Request, String> {
    let mut first = String::new();
    rdr.read_line(&mut first).map_err(|e| e.to_string())?;
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("").to_uppercase();
    let path = it.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if rdr.read_line(&mut h).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let h = h.trim_end().to_string();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }
    Ok(Request { method, path, headers, content_length })
}

fn respond(w: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = w.write_all(head.as_bytes());
    let _ = w.write_all(body);
    let _ = w.flush();
}

pub fn handle_conn(state: &HttpState, stream: TcpStream) {
    let mut rdr = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let req = match read_request(&mut rdr) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut wtr = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/ws") => ws_upgrade(state, &req, &mut wtr),
        ("GET", "/") | ("GET", "/index.html") => {
            respond(&mut wtr, "200 OK", "text/html; charset=utf-8", state.web_index.as_bytes())
        }
        ("GET", "/app.js") => respond(&mut wtr, "200 OK", "text/javascript; charset=utf-8", state.web_app.as_bytes()),
        ("GET", "/style.css") => respond(&mut wtr, "200 OK", "text/css; charset=utf-8", state.web_style.as_bytes()),
        ("GET", "/api/stats") => respond(&mut wtr, "200 OK", "application/json; charset=utf-8", stats_json(state).as_bytes()),
        ("POST", "/api/inject") => {
            if req.content_length > 0 && req.content_length < 4096 {
                let mut body = vec![0u8; req.content_length];
                let _ = rdr.read_exact(&mut body);
                respond(&mut wtr, "200 OK", "application/json; charset=utf-8", handle_inject(state, &body).as_bytes());
            } else {
                respond(&mut wtr, "400 Bad Request", "text/plain; charset=utf-8", b"bad body length");
            }
        }
        _ => respond(&mut wtr, "404 Not Found", "text/plain; charset=utf-8", b"not found"),
    }
}

fn stats_json(state: &HttpState) -> String {
    let st = state.store.lock().unwrap();
    let warn_sample: Vec<String> = st.warnings.iter().rev().take(3).cloned().collect();
    json!({
        "frames": state.stats.frames.load(Ordering::Relaxed),
        "signal_pts": state.stats.signal_pts.load(Ordering::Relaxed),
        "events": state.stats.events.load(Ordering::Relaxed),
        "records": st.records.len(),
        "parse_ok": st.ok,
        "parse_bad": st.bad,
        "warn_sample": warn_sample,
        "uptime_s": state.stats.t0.elapsed().as_secs(),
        "tsrc": "sw",
        "level": "L0",
        "note": "模拟源(ADR-5 L0 收包时刻)",
        "session": "web-demo",
    })
    .to_string()
}

fn handle_inject(state: &HttpState, body: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    match kind {
        "temp_fault" => {
            let now = !state.inject.temp_fault.load(Ordering::Relaxed);
            state.inject.temp_fault.store(now, Ordering::Relaxed);
            json!({"ok": true, "temp_fault": now}).to_string()
        }
        "hb_stall" => {
            *state.inject.hb_stall_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(3));
            json!({"ok": true, "hb_stall_s": 3}).to_string()
        }
        _ => json!({"ok": false, "error": "unknown kind"}).to_string(),
    }
}

fn parse_id(v: &serde_json::Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return Some(n as u32);
    }
    let s = v.as_str()?.trim().to_string();
    let lower = s.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

fn ws_upgrade(state: &HttpState, req: &Request, wtr: &mut TcpStream) {
    let key = req.headers.get("sec-websocket-key").cloned().unwrap_or_default();
    if key.is_empty() {
        respond(wtr, "400 Bad Request", "text/plain; charset=utf-8", b"missing Sec-WebSocket-Key");
        return;
    }
    let accept = ws::accept_key(&key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if wtr.write_all(resp.as_bytes()).is_err() {
        return;
    }
    let _ = wtr.flush();

    let (tx, rx) = mpsc::sync_channel::<String>(1024);
    let filter = Arc::new(Mutex::new(Filter::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let id = CLIENT_SEQ.fetch_add(1, Ordering::Relaxed);
    state.hub.clients.lock().unwrap().push(ClientHandle { id, tx, filter: filter.clone(), stop: stop.clone() });

    // 读线程:控制消息(set_filter)/ping/close
    let mut rsock = match wtr.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut wsock = match wtr.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let stop_r = stop.clone();
    let filter_r = filter.clone();
    let reader = std::thread::Builder::new()
        .name("ws-read".into())
        .spawn(move || {
            loop {
                if stop_r.load(Ordering::Relaxed) {
                    break;
                }
                match ws::read_frame(&mut rsock) {
                    Ok((op, data)) => match op {
                        0x8 => break, // close
                        0x9 => {
                            let _ = ws::write_frame(&mut wsock, 0xA, &data); // ping → pong
                        }
                        0x1 => {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data) {
                                if v.get("type").and_then(|t| t.as_str()) == Some("set_filter") {
                                    let ids: Option<Vec<u32>> =
                                        v.get("ids").and_then(|x| x.as_array()).map(|arr| arr.iter().filter_map(parse_id).collect());
                                    let dir = v
                                        .get("dir")
                                        .and_then(|d| d.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_default();
                                    *filter_r.lock().unwrap() = Filter { ids, dir };
                                }
                            }
                        }
                        _ => {}
                    },
                    Err(_) => break,
                }
            }
            stop_r.store(true, Ordering::Relaxed);
        })
        .unwrap();

    // 写线程(本线程):从 hub 队列取信封消息写帧
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(msg) => {
                if ws::write_text(wtr, &msg).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    state.hub.clients.lock().unwrap().retain(|c| c.id != id);
    let _ = reader.join();
}
