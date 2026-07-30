//! End-to-end test for the federated broker mesh: two brokers peered with
//! each other relay a task and its reply between two agents that are each
//! connected to a different broker. This exercises real processes over real
//! WebSocket connections (including the Noise handshake), rather than
//! unit-testing routing logic in isolation, because that is where the
//! actual federation behavior lives.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_line_reader<R: Read + Send + 'static>(reader: R, tx: Sender<String>) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

fn wait_for(rx: &Receiver<String>, needle: &str, timeout: Duration) -> bool {
    wait_for_all(rx, &[needle], timeout)
}

/// Waits for a single line that contains every given substring.
fn wait_for_all(rx: &Receiver<String>, needles: &[&str], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) if needles.iter().all(|needle| line.contains(needle)) => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Every key file in this test is encrypted with this fixed passphrase, fed
/// in via AERONET_KEY_PASSPHRASE so the CLI never blocks on an interactive
/// prompt (this process has no TTY under `cargo test`).
const TEST_PASSPHRASE: &str = "federation-test-passphrase";

fn generate_key(dir: &Path, name: &str) -> String {
    let out = dir.join(format!("{name}.key.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_aeronet-key"))
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .arg("generate")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("failed to run aeronet-key generate");
    assert!(output.status.success(), "generate failed: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn issue_capability(dir: &Path, issuer_key: &Path, grantee_did: &str, out_name: &str) -> PathBuf {
    let out = dir.join(out_name);
    let status = Command::new(env!("CARGO_BIN_EXE_aeronet-key"))
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .arg("issue")
        .arg("--issuer-key")
        .arg(issuer_key)
        .arg("--grantee")
        .arg(grantee_did)
        .arg("--out")
        .arg(&out)
        .status()
        .expect("failed to run aeronet-key issue");
    assert!(status.success());
    out
}

#[test]
fn task_and_reply_cross_a_federated_broker_mesh() {
    let dir = tempfile::tempdir().unwrap();
    let (log_tx, log_rx) = channel::<String>();

    let broker_x_did = generate_key(dir.path(), "broker-x");
    let broker_y_did = generate_key(dir.path(), "broker-y");
    let alice_did = generate_key(dir.path(), "alice");
    let bob_did = generate_key(dir.path(), "bob");

    // "alice-to-bob" lets Alice message Bob, so Bob (the audience) issues it.
    let alice_to_bob = issue_capability(
        dir.path(),
        &dir.path().join("bob.key.json"),
        &alice_did,
        "alice-to-bob.cap.json",
    );
    // "bob-to-alice" lets Bob reply to Alice, so Alice issues it.
    let bob_to_alice = issue_capability(
        dir.path(),
        &dir.path().join("alice.key.json"),
        &bob_did,
        "bob-to-alice.cap.json",
    );

    let listen_x = "127.0.0.1:18787";
    let listen_y = "127.0.0.1:18788";

    let mut broker_x = Command::new(env!("CARGO_BIN_EXE_broker"))
        .env("RUST_LOG", "info")
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--listen", listen_x])
        .arg("--state-db")
        .arg(dir.path().join("x.db"))
        .arg("--audit-log")
        .arg(dir.path().join("x.jsonl"))
        .arg("--broker-key")
        .arg(dir.path().join("broker-x.key.json"))
        .arg("--peer-broker")
        .arg(format!("ws://127.0.0.1:18788@{broker_y_did}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn broker X");
    spawn_line_reader(broker_x.stdout.take().unwrap(), log_tx.clone());
    spawn_line_reader(broker_x.stderr.take().unwrap(), log_tx.clone());
    let _broker_x = ChildGuard(broker_x);

    let mut broker_y = Command::new(env!("CARGO_BIN_EXE_broker"))
        .env("RUST_LOG", "info")
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--listen", listen_y])
        .arg("--state-db")
        .arg(dir.path().join("y.db"))
        .arg("--audit-log")
        .arg(dir.path().join("y.jsonl"))
        .arg("--broker-key")
        .arg(dir.path().join("broker-y.key.json"))
        .arg("--peer-broker")
        .arg(format!("ws://127.0.0.1:18787@{broker_x_did}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn broker Y");
    spawn_line_reader(broker_y.stdout.take().unwrap(), log_tx.clone());
    spawn_line_reader(broker_y.stderr.take().unwrap(), log_tx.clone());
    let _broker_y = ChildGuard(broker_y);

    assert!(
        wait_for_port(listen_x, Duration::from_secs(5)),
        "broker X never started listening"
    );
    assert!(
        wait_for_port(listen_y, Duration::from_secs(5)),
        "broker Y never started listening"
    );
    assert!(
        wait_for(
            &log_rx,
            "federation link established",
            Duration::from_secs(10)
        ),
        "first federation link did not establish"
    );
    assert!(
        wait_for(
            &log_rx,
            "federation link established",
            Duration::from_secs(10)
        ),
        "second federation link did not establish"
    );

    let mut bob = Command::new(env!("CARGO_BIN_EXE_agent"))
        .env("RUST_LOG", "info")
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .arg("--key")
        .arg(dir.path().join("bob.key.json"))
        .arg("--peer")
        .arg(&alice_did)
        .arg("--capability")
        .arg(&bob_to_alice)
        .args([
            "--provider",
            "echo",
            "--max-turns",
            "3",
            "--broker",
            listen_y,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bob");
    spawn_line_reader(bob.stdout.take().unwrap(), log_tx.clone());
    spawn_line_reader(bob.stderr.take().unwrap(), log_tx.clone());
    let _bob = ChildGuard(bob);

    assert!(
        wait_for(&log_rx, "agent connected", Duration::from_secs(5)),
        "bob never connected to broker Y"
    );

    let mut alice = Command::new(env!("CARGO_BIN_EXE_agent"))
        .env("RUST_LOG", "info")
        .env("AERONET_KEY_PASSPHRASE", TEST_PASSPHRASE)
        .arg("--key")
        .arg(dir.path().join("alice.key.json"))
        .arg("--peer")
        .arg(&bob_did)
        .arg("--capability")
        .arg(&alice_to_bob)
        .args([
            "--provider",
            "echo",
            "--max-turns",
            "1",
            "--broker",
            listen_x,
        ])
        .arg("--kickoff")
        .arg("federation integration test")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn alice");
    spawn_line_reader(alice.stdout.take().unwrap(), log_tx.clone());
    spawn_line_reader(alice.stderr.take().unwrap(), log_tx.clone());
    let _alice = ChildGuard(alice);

    // The recipient is never connected to broker X, so a real federation
    // forward has to happen for this to succeed — proving the mesh, not
    // just local delivery, actually carried the message.
    assert!(
        wait_for(
            &log_rx,
            "forwarded to federation peers",
            Duration::from_secs(10)
        ),
        "broker X never forwarded the task to its federation peer"
    );

    // Only alice's own process prints "received from <bob_did>": this is
    // the reply having round-tripped Alice -> X -> (federation) -> Y -> Bob
    // -> Y -> (federation) -> X -> Alice.
    assert!(
        wait_for_all(
            &log_rx,
            &["received from", &bob_did],
            Duration::from_secs(10)
        ),
        "alice never received bob's reply back across the federation link"
    );
}
