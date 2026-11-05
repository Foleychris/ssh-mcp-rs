//! Integration tests for client authentication and ssh_config resolution.
//!
//! Self-contained: each test starts its own sshd and ssh-agent on loopback,
//! with throwaway keys and a throwaway CA, and drives `sshmux-mcp --stdio`.
//! Needs OpenSSH (`sshd`, `ssh-keygen`, `ssh-agent`, `ssh-add`), so it is
//! ignored by default:
//!
//!   cargo test --release --test auth -- --ignored --test-threads=1
//!
//! sshd runs as the current user (no root needed) and only accepts that user.

mod common;
use common::*;
use serde_json::json;
use std::process::{Command, Stdio};

#[test]
#[ignore]
fn key_file_default_still_works() {
    let mut lab = Lab::new("keyfile");
    keygen(&lab.p("k"), "");
    lab.authorize("k");
    lab.start_sshd();
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(
        !e && t.contains("reachable") && t.contains("key file"),
        "{t}"
    );
}

#[test]
#[ignore]
fn agent_only() {
    let mut lab = Lab::new("agent");
    keygen(&lab.p("k"), "");
    lab.authorize("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("k");
    std::fs::remove_file(lab.p("k")).unwrap(); // only the agent has it now
    let cfg = lab.config("", false); // no key_file -> auth defaults to ["agent"]
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("authenticated with agent key"), "{t}");
    // Without the agent socket, it fails and says why, without running anything.
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(
        e && t.contains("SSH_AUTH_SOCK") && t.contains("Nothing was run"),
        "{t}"
    );
}

#[test]
#[ignore]
fn certificate_only_from_key_file() {
    let mut lab = Lab::new("cert");
    keygen(&lab.p("k"), "");
    lab.certify("k"); // writes k-cert.pub; key is NOT in authorized_keys
    lab.start_sshd();
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(!e && t.contains("with certificate"), "{t}");
}

#[test]
#[ignore]
fn certificate_held_by_agent() {
    let mut lab = Lab::new("agentcert");
    keygen(&lab.p("k"), "");
    lab.certify("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("k"); // ssh-add also loads k-cert.pub
    let cfg = lab.config("auth = [\"agent\"]", false);
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("agent certificate"), "{t}");
}

#[test]
#[ignore]
fn passphrase_key_file() {
    let mut lab = Lab::new("pass");
    keygen(&lab.p("k"), "correct horse");
    lab.authorize("k");
    lab.start_sshd();
    // key_file alone: refuses to start and says how to fix it.
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(e && t.contains("passphrase-protected"), "{t}");
    // With the agent holding it, the same key works.
    lab.start_agent();
    std::fs::write(lab.p("askpass"), "#!/bin/sh\necho 'correct horse'\n").unwrap();
    run(Command::new("chmod").arg("755").arg(lab.p("askpass")));
    run(Command::new("ssh-add")
        .arg("-q")
        .arg(lab.p("k"))
        .env("SSH_AUTH_SOCK", lab.sock())
        .env("SSH_ASKPASS", lab.p("askpass"))
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "x")
        .stdin(Stdio::null()));
    let cfg = lab.config(
        &format!(
            "key_file = \"{}\"\nauth = [\"agent\", \"key_file\"]",
            lab.p("k").display()
        ),
        false,
    );
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("agent key"), "{t}");
}

#[test]
#[ignore]
fn stops_before_max_auth_tries() {
    let mut lab = Lab::new("many");
    lab.start_sshd();
    lab.start_agent();
    for i in 0..7 {
        keygen(&lab.p(&format!("k{i}")), "");
        lab.agent_add(&format!("k{i}"));
    }
    lab.authorize("k6"); // only the 7th; beyond the cap
    let cfg = lab.config("auth = [\"agent\"]", false);
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(e && t.contains("stopped after 5 attempts"), "{t}");
    assert_eq!(t.matches(": rejected").count(), 5, "{t}");
}

#[test]
#[ignore]
fn ssh_config_alias_identityfile_and_hostkeyalias() {
    let mut lab = Lab::new("sshcfg");
    keygen(&lab.p("k"), "");
    keygen(&lab.p("decoy"), "");
    lab.authorize("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("decoy"); // an agent key that is NOT authorized
    lab.agent_add("k");
    std::fs::write(
        lab.p("ssh_config"),
        format!(
            "Host lab-alias\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  HostKeyAlias lab-alias\n\
             Host only-decoy\n  HostName 127.0.0.1\n  Port {port}\n  User {u}\n  IdentityFile {decoy}\n  IdentitiesOnly yes\n  HostKeyAlias lab-alias\n\
             Host jumpy\n  HostName 127.0.0.1\n  ProxyJump bastion.example.com\n\
             Host *\n  User nobody-by-default\n",
            lab.port,
            user(),
            lab.p("k").display(),
            port = lab.port,
            u = user(),
            decoy = lab.p("decoy").display(),
        ),
    )
    .unwrap();
    std::fs::remove_file(lab.p("k")).unwrap();
    // k.pub stays: it identifies which agent key IdentitiesOnly allows.
    let cfg = lab.config(
        &format!(
            "ssh_config = \"{}\"\nallow_unlisted_hosts = false\nauth = [\"agent\"]",
            lab.p("ssh_config").display()
        ),
        true,
    );
    // Alias resolves to HostName/Port/User; the host key is checked under
    // HostKeyAlias (known_hosts has "lab-alias", not "[127.0.0.1]:port"...
    // which it also has, so remove that line to prove the alias is used).
    let kh = std::fs::read_to_string(lab.p("known_hosts")).unwrap();
    std::fs::write(
        lab.p("known_hosts"),
        kh.lines()
            .filter(|l| l.starts_with("lab-alias"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let (e, t) = test_conn(&lab, &cfg, true, "lab-alias");
    assert!(
        !e && t.contains("reachable") && t.contains("agent key"),
        "{t}"
    );
    // IdentitiesOnly restricts the agent to the IdentityFile's key: with only
    // the (unauthorized) decoy named, exactly one key is offered and the
    // authorized one is never tried.
    let (e, t) = test_conn(&lab, &cfg, true, "only-decoy");
    assert!(e && t.matches(": rejected").count() == 1, "{t}");
    // A host named only via a wildcard isn't "configured" when unlisted hosts are off.
    let (e, t) = test_conn(&lab, &cfg, true, "somewhere-else");
    assert!(e && t.contains("unknown host"), "{t}");
    // ProxyJump becomes `ssh -W` through the jump host; this one doesn't
    // exist, so the error carries the proxy's own complaint.
    let (e, t) = test_conn(&lab, &cfg, true, "jumpy");
    assert!(
        e && t.contains("ssh_config ProxyJump") && t.contains("proxy exited"),
        "{t}"
    );
    // list_hosts shows the ssh_config hosts and their transport.
    let (_, t) = call(&lab, &cfg, true, "list_hosts", json!({}));
    assert!(
        t.contains("lab-alias")
            && t.contains("jumpy")
            && t.contains("proxy: ssh (ssh_config ProxyJump)"),
        "{t}"
    );
}
