// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

pub(super) fn resolve_feed(nightly: bool, feed: Option<&str>, repo: Option<&str>) -> String {
    if let Some(feed) = feed.filter(|s| !s.is_empty()) {
        return feed.to_owned();
    }
    let repo = repo
        .filter(|s| !s.is_empty())
        .or(option_env!("LIVI_UPDATE_REPO").filter(|s| !s.is_empty()))
        .unwrap_or("f-io/LIVI");
    let endpoint = if nightly { "tags/nightly" } else { "latest" };
    format!("https://api.github.com/repos/{repo}/releases/{endpoint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_fork_owns_default_feed() {
        let repo = option_env!("LIVI_UPDATE_REPO")
            .filter(|s| !s.is_empty())
            .unwrap_or("f-io/LIVI");
        assert_eq!(
            resolve_feed(false, None, None),
            format!("https://api.github.com/repos/{repo}/releases/latest")
        );
        assert_eq!(
            resolve_feed(true, Some(""), Some("")),
            format!("https://api.github.com/repos/{repo}/releases/tags/nightly")
        );
    }

    #[test]
    fn runtime_overrides_take_precedence() {
        assert_eq!(
            resolve_feed(
                false,
                Some("https://updates.example/feed"),
                Some("other/repo")
            ),
            "https://updates.example/feed"
        );
        assert_eq!(
            resolve_feed(true, None, Some("other/repo")),
            "https://api.github.com/repos/other/repo/releases/tags/nightly"
        );
    }
}
