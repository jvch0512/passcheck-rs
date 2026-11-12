use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], input: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_passcheck"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn weak_password_fails_and_strong_passes() {
    let (code, out, _) = run(&[], "Password1\n");
    assert_eq!(code, 1);
    assert!(out.contains("very weak") || out.contains("weak"));
    assert!(out.contains("common password"));
    let (code, out, _) = run(&[], "vR8#kQ2$mL5!xZ9@nB4\n");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("strong"));
}

#[test]
fn the_password_is_never_printed() {
    let secret = "Zq7#unique-marker-Zq7";
    let (_, out, err) = run(&[], &format!("{secret}\n"));
    assert!(!out.contains(secret) && !err.contains(secret));
    let (_, out, err) = run(&["--batch"], &format!("{secret}\nletmein\n"));
    assert!(!out.contains(secret) && !err.contains(secret));
    assert!(out.contains("line    1") && out.contains("line    2"));
}

#[test]
fn batch_mode_threshold_and_usage() {
    let (code, out, _) = run(
        &["--batch", "--min-score", "1"],
        "password\nvR8#kQ2$mL5!xZ9@nB4\n\n",
    );
    assert_eq!(code, 1);
    assert!(out.contains("1 of 2 below"));
    let (code, _, _) = run(&["--batch", "--min-score", "0"], "password\n");
    assert_eq!(code, 0);
    assert_eq!(run(&["--bogus"], "x\n").0, 2);
    assert_eq!(run(&["--min-score", "9"], "x\n").0, 2);
    assert_eq!(run(&[], "").0, 2);
}
