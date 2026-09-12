use std::process::{Command, Stdio};

pub fn get_recent_changes() -> Option<String> {
    // 1. Check if git is available and we are in a git repository
    let is_git_repo = Command::new("git")
        .args(["--no-pager", "rev-parse", "--is-inside-work-tree"])
        .stdin(Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !is_git_repo {
        return None;
    }

    // 2. Try to get uncommitted changes first (working directory diff)
    let mut diff = Command::new("git")
        .args(["--no-pager", "diff", "--no-color", "HEAD"])
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // 3. If no uncommitted changes, get the last commit
    if diff.trim().is_empty() {
        diff = Command::new("git")
            .args(["--no-pager", "show", "--no-color", "HEAD"])
            .stdin(Stdio::null())
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
    }

    // Limit diff size to prevent token blowup (strictly respecting UTF-8 char boundaries)
    truncate_diff_safe(&mut diff, 5000);

    if diff.trim().is_empty() {
        None
    } else {
        Some(diff)
    }
}

pub fn truncate_diff_safe(diff: &mut String, max_bytes: usize) {
    if diff.len() > max_bytes {
        let boundary = diff.floor_char_boundary(max_bytes);
        diff.truncate(boundary);
        diff.push_str("\n... (diff truncated)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_diff_safe_multibyte_utf8() {
        // Construct string with 3-byte characters (Japanese / Chinese / Indonesian)
        // '日' is 3 bytes (0xE6 0x97 0xA5)
        let base = "日本語テスト".repeat(10); // 180 bytes
        let mut s = base.clone();
        // Cut right in the middle of a 3-byte character (byte index 10 is inside character at bytes 9..12)
        truncate_diff_safe(&mut s, 10);
        assert!(s.ends_with("\n... (diff truncated)"));
        // Floor of 10 for 3-byte chars should be 9 (3 * 3)
        assert_eq!(&s[..9], "日本語");
    }
}
