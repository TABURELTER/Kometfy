//! Release channel. A "dev" build (`--features dev-channel`) lives beside the stable app without touching it: its
//! own data folder, ports, single-instance lock, window title, sign-in task and Run key, so the two can run at
//! once and neither can break the other's settings.
//!
//! Stable keeps the names it has always had (users' installs, the installer and the uninstaller know them), so
//! `stable_names_never_change` fails when one of them is touched. What is NOT split yet: the macOS privileged
//! helpers (`/Library/PrivilegedHelperTools/dev.prismroute.*`), see TODO.md.

pub const DEV: bool = cfg!(feature = "dev-channel");

pub struct Names {
    /// Folder under the platform's app-data root (`%APPDATA%`, `~/Library/Application Support`).
    pub data_dir: &'static str,
    /// Bundle identifier: also the macOS `open -b` target.
    pub bundle_id: &'static str,
    pub window_title: &'static str,
    pub mixed_port: u16,
    pub controller_port: u16,
    /// Local control API of our own builds (docs/DEV_API.md).
    pub dev_api_port: u16,
    /// Scheduled task that starts the app elevated, and the autostart Run value.
    pub task: &'static str,
    pub mutex: &'static str,
    pub show_event: &'static str,
    pub preview_mutex: &'static str,
}

pub const fn names(dev: bool) -> Names {
    if dev {
        Names {
            data_dir: "dev.kometfy.dev",
            bundle_id: "dev.kometfy.dev",
            window_title: "Kometfy DEV",
            mixed_port: 27897,
            controller_port: 29097,
            dev_api_port: 47921,
            task: "KometfyDev",
            mutex: "Local\\KometfyDev.SingleInstance",
            show_event: "Local\\KometfyDev.Show",
            preview_mutex: "Local\\KometfyDev.UIPreview",
        }
    } else {
        Names {
            data_dir: "dev.prismroute.console",
            bundle_id: "dev.prismroute.console",
            window_title: "Kometfy",
            mixed_port: 17897,
            controller_port: 19097,
            dev_api_port: 47821,
            task: "PrismRoute",
            mutex: "Local\\PrismRouteConnect.SingleInstance",
            show_event: "Local\\PrismRouteConnect.Show",
            preview_mutex: "Local\\PrismRouteConnect.UIPreview",
        }
    }
}

/// The names of the channel this binary was built for.
pub const NOW: Names = names(DEV);

#[cfg(test)]
mod tests {
    use super::names;

    fn strings(n: &super::Names) -> [&'static str; 7] {
        [n.data_dir, n.bundle_id, n.window_title, n.task, n.mutex, n.show_event, n.preview_mutex]
    }

    #[test]
    fn dev_shares_nothing_with_stable() {
        let (d, s) = (names(true), names(false));
        for (a, b) in strings(&d).iter().zip(strings(&s).iter()) {
            assert_ne!(a, b);
        }
        assert_ne!(d.mixed_port, s.mixed_port);
        assert_ne!(d.controller_port, s.controller_port);
        assert_ne!(d.dev_api_port, s.dev_api_port);
        // one name per purpose inside a channel
        for n in [&d, &s] {
            assert_ne!(n.mutex, n.show_event);
            assert_ne!(n.mutex, n.preview_mutex);
        }
    }

    #[test]
    fn stable_names_never_change() {
        let s = names(false);
        assert_eq!(s.data_dir, "dev.prismroute.console");
        assert_eq!(s.task, "PrismRoute");
        assert_eq!(s.mutex, "Local\\PrismRouteConnect.SingleInstance");
        assert_eq!(s.show_event, "Local\\PrismRouteConnect.Show");
        assert_eq!((s.mixed_port, s.controller_port, s.dev_api_port), (17897, 19097, 47821));
    }
}
