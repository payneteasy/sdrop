//! TUI terminal handling in a real pseudo-terminal (`script`): a shown secret is cleared before
//! leaving the alternate screen on an error and on a panic, and the input mode is restored.
#![cfg(all(unix, feature = "test-loopback"))]

use std::process::Command;

const MARK: &str = "MARK-SECRET-7f3a";

/// Runs `sdrop tui` in a pseudo-terminal, then `stty -a` in the same terminal; returns the output.
fn in_pty(exit: &str) -> String {
    let inner = format!(
        "stty rows 24 cols 80; SDROP_ORIGIN=http://127.0.0.1:9 SDROP_TEST_TUI_MARKER={MARK} SDROP_TEST_TUI_EXIT={exit} '{}' tui; echo EXIT=$?; stty -a",
        env!("CARGO_BIN_EXE_sdrop")
    );
    let out = if cfg!(target_os = "macos") {
        Command::new("script")
            .args(["-q", "/dev/null", "sh", "-c", &inner])
            .output()
    } else {
        Command::new("script")
            .args(["-qec", &format!("sh -c \"{inner}\""), "/dev/null"])
            .output()
    }
    .expect("script(1) is needed for this test");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn check(exit: &str) {
    let out = in_pty(exit);
    let enter = out.find("\x1b[?1049h").expect("alternate screen entered");
    let mark = out.rfind(MARK).expect("secret marker shown");
    let leave = out.rfind("\x1b[?1049l").expect("alternate screen left");
    assert!(enter < mark && mark < leave, "{out:?}");
    // The screen is cleared after the secret was shown and before leaving the alternate screen.
    let clear = out[mark..leave].rfind("\x1b[2J").map(|i| mark + i);
    assert!(
        clear.is_some(),
        "no clear between the secret and leaving: {out:?}"
    );
    // Nothing of the secret is written after leaving the alternate screen.
    assert!(!out[leave..].contains(MARK), "{out:?}");
    // The terminal is back in canonical (cooked) mode.
    let stty = &out[leave..];
    assert!(
        stty.split_whitespace().any(|w| w == "icanon"),
        "raw mode not restored: {stty:?}"
    );
    assert!(out.contains("EXIT=") && !out.contains("EXIT=0"), "{out:?}");
}

#[test]
fn error_clears_secret_and_restores_terminal() {
    check("error");
}

#[test]
fn panic_clears_secret_and_restores_terminal() {
    check("panic");
}
