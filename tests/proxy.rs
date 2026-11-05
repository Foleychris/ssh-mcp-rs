//! Integration tests for the ProxyCommand transport, through `nc` to a
//! throwaway sshd (see tests/common). Needs OpenSSH and OpenBSD/GNU `nc`:
//!
//!   cargo test --release --test proxy -- --ignored --test-threads=1

mod common;
use common::*;
use serde_json::json;
use std::process::Command;
use std::time::{Duration, Instant};

/// Processes whose full command line matches `pattern` exactly (pgrep -x -f).
fn count(pattern: &str) -> usize {
    let out = Command::new("pgrep")
        .args(["-x", "-f", pattern])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

fn wait_count(pattern: &str, want: usize) {
    let t0 = Instant::now();
    while count(pattern) != want {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "expected {want} × {pattern:?}, found {}",
            count(pattern)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A lab with an authorized key `k`, and a config whose extra TOML is `extra`
/// (tables allowed: no [hosts.lab] is added).
fn lab_with_key(name: &str) -> Lab {
    let mut lab = Lab::new(name);
    keygen(&lab.p("k"), "");
    lab.authorize("k");
    lab.start_sshd();
    lab
}

fn cfg(lab: &Lab, extra: &str) -> std::path::PathBuf {
    lab.config(
        &format!("key_file = \"{}\"\n{extra}", lab.p("k").display()),
        true,
    )
}

fn trust_name(lab: &Lab, name: &str) {
    let k = std::fs::read_to_string(lab.p("host_key.pub")).unwrap();
    let k: Vec<&str> = k.split_whitespace().take(2).collect();
    let mut kh = std::fs::read_to_string(lab.p("known_hosts")).unwrap();
    kh.push_str(&format!("{name} {}\n", k.join(" ")));
    std::fs::write(lab.p("known_hosts"), kh).unwrap();
}

#[test]
#[ignore]
fn all_tools_through_proxy_command() {
    let lab = lab_with_key("px-tools");
    let nc = format!("nc 127.0.0.1 {}", lab.port);
    let cfg = cfg(
        &lab,
        &format!(
            "[hosts.lab]\naddress = \"127.0.0.1\"\nport = {}\nproxy_command = \"nc %h %p\"\n",
            lab.port
        ),
    );
    let mut s = Session::start(&lab, &cfg, false);

    let (e, t) = s.one(1, "test_ssh_connection", json!({"hostname": "lab"}));
    assert!(!e && t.contains("transport: proxy: nc (hosts.lab)"), "{t}");
    assert!(count(&nc) >= 1, "the proxy process should be running");

    // 12 concurrent commands: more than one connection's worth of channels,
    // so several proxied connections carry them.
    let t0 = Instant::now();
    for i in 100..112 {
        s.call(
            i,
            "execute_command",
            json!({"hostname": "lab", "command": format!("sleep 1; echo m-{i}")}),
        );
    }
    let got = s.wait(&(100..112).collect::<Vec<_>>());
    for (id, (e, t)) in &got {
        assert!(!e && t.contains(&format!("m-{id}")), "{id}: {t}");
    }
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "ran serially? {:?}",
        t0.elapsed()
    );
    assert!(
        count(&nc) >= 2,
        "expected several proxied connections, found {}",
        count(&nc)
    );

    // File tools.
    let f = lab.p("f.txt").display().to_string();
    let (e, t) = s.one(
        200,
        "write_file",
        json!({"hostname": "lab", "path": f, "content": "alpha\nbeta\n"}),
    );
    assert!(!e && t.contains("verified"), "{t}");
    let (e, t) = s.one(
        201,
        "edit_file",
        json!({"hostname": "lab", "path": f, "old_string": "beta", "new_string": "gamma"}),
    );
    assert!(!e, "{t}");
    let (e, t) = s.one(202, "read_file", json!({"hostname": "lab", "path": f}));
    assert!(!e && t.contains("alpha\ngamma"), "{t}");

    // cancel_run kills the remote process through the proxy.
    let (_, t) = s.one(
        300,
        "execute_command",
        json!({"hostname": "lab", "command": "sleep 377", "background": true}),
    );
    let run_id = t
        .split("run_id=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    wait_count("sleep 377", 1);
    let (e, t) = s.one(301, "cancel_run", json!({"run_id": run_id}));
    assert!(!e && t.contains("cancelled"), "{t}");
    wait_count("sleep 377", 0);

    let (_, t) = s.one(400, "list_hosts", json!({}));
    assert!(
        t.contains("[proxy: nc (hosts.lab)]") && t.contains(" via nc#"),
        "{t}"
    );

    s.close();
    // The server stopped its proxies on the way out.
    wait_count(&nc, 0);
}

#[test]
#[ignore]
fn proxy_rules_route_unlisted_names() {
    let lab = lab_with_key("px-rules");
    trust_name(&lab, "i-0123456789abcdef0"); // host key under the name, as with SSM
    let cfg = cfg(
        &lab,
        &format!(
            "allow_unlisted_hosts = false\n[[proxy_rules]]\nmatch = \"^i-[0-9a-f]{{8,17}}$\"\nproxy_command = \"nc 127.0.0.1 {}\"\n",
            lab.port
        ),
    );
    let mut s = Session::start(&lab, &cfg, false);
    let (e, t) = s.one(
        1,
        "test_ssh_connection",
        json!({"hostname": "i-0123456789abcdef0"}),
    );
    assert!(!e && t.contains("proxy: nc (proxy_rules[0])"), "{t}");
    // Names the rule doesn't match are still unlisted (and refused).
    let (e, t) = s.one(2, "test_ssh_connection", json!({"hostname": "i-nothex"}));
    assert!(e && t.contains("unknown host"), "{t}");
    s.close();
}

#[test]
#[ignore]
fn ssh_config_proxycommand_runs_through_a_shell() {
    let lab = lab_with_key("px-sshcfg");
    std::fs::write(
        lab.p("ssh_config"),
        format!(
            "Host viaproxy\n  HostName 127.0.0.1\n  Port {}\n  ProxyCommand nc %h %p 2>/dev/null\n",
            lab.port
        ),
    )
    .unwrap();
    let cfg = cfg(
        &lab,
        &format!("ssh_config = \"{}\"\n", lab.p("ssh_config").display()),
    );
    let mut s = Session::start(&lab, &cfg, false);
    let (e, t) = s.one(1, "test_ssh_connection", json!({"hostname": "viaproxy"}));
    assert!(
        !e && t.contains("proxy: sh -c (ssh_config ProxyCommand)"),
        "{t}"
    );
    s.close();
}

#[test]
#[ignore]
fn failing_proxy_reports_its_stderr() {
    let lab = lab_with_key("px-fail");
    let cfg = cfg(
        &lab,
        "[hosts.broken]\naddress = \"i-0123456789abcdef0\"\n\
         proxy_command = \"sh -c 'echo SessionManagerPlugin is not found >&2; exit 255'\"\n",
    );
    let mut s = Session::start(&lab, &cfg, false);
    let (e, t) = s.one(1, "test_ssh_connection", json!({"hostname": "broken"}));
    assert!(
        e && t.contains("SessionManagerPlugin is not found") && t.contains("exit status: 255"),
        "{t}"
    );
    s.close();
}

#[test]
#[ignore]
fn slow_proxy_times_out_and_its_process_group_is_killed() {
    let lab = lab_with_key("px-slow");
    // sh starts a child (like aws starting session-manager-plugin); both must go.
    let cfg = cfg(
        &lab,
        "[hosts.slow]\naddress = \"slow.example\"\nconnect_timeout_secs = 2\n\
         proxy_command = \"sh -c 'sleep 33; true'\"\n",
    );
    let mut s = Session::start(&lab, &cfg, false);
    let t0 = Instant::now();
    let (e, t) = s.one(1, "test_ssh_connection", json!({"hostname": "slow"}));
    assert!(
        e && t.contains("timed out connecting to slow after 2s")
            && t.contains("connect_timeout_secs"),
        "{t}"
    );
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    wait_count("sleep 33", 0);
    s.close();
}

#[test]
#[ignore]
fn values_that_could_inject_are_refused() {
    let lab = lab_with_key("px-inject");
    let marker = lab.p("pwned");
    let cfg = cfg(
        &lab,
        "[[proxy_rules]]\nmatch = \".*\"\nproxy_command = \"nc %h %p\"\nproxy_shell = true\n",
    );
    let mut s = Session::start(&lab, &cfg, false);
    for (i, h) in [
        "x$(touch${IFS}pwned)",
        "x;touch${IFS}pwned",
        "x`id`",
        "x|id",
    ]
    .iter()
    .enumerate()
    {
        let (e, t) = s.one(i as i64, "test_ssh_connection", json!({"hostname": h}));
        assert!(
            e && (t.contains("can't be used in a proxy command") || t.contains("invalid hostname")),
            "{h}: {t}"
        );
    }
    s.close();
    assert!(!marker.exists());
    assert!(!std::path::Path::new("pwned").exists());
}
