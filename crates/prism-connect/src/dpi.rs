//! DPI bypass: how the TLS handshake is cut into pieces before it reaches the censor's box.
//!
//! The values come from the user (Settings) or from the subscription (Happ `fragmentation-*`
//! headers). Only Xray can do this, so the settings are applied when a server is run by Xray
//! (see `xray_conf`). Ranges are Xray-style strings: `"100-200"` or a single `"50"`.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dpi {
    /// Which packets are cut: `tlshello` (the first TLS record) or a range such as `1-3`.
    pub packets: String,
    /// Piece size in bytes.
    pub length: String,
    /// Pause between pieces in milliseconds.
    pub interval: String,
    /// Upper limit of pieces per packet. Empty: no limit.
    pub max_split: String,
}

impl Default for Dpi {
    fn default() -> Self {
        Self {
            packets: "tlshello".into(),
            length: "100-200".into(),
            interval: "10-20".into(),
            max_split: String::new(),
        }
    }
}

/// `"50"` or `"50-100"` inside `min..=max`, written back in canonical form.
fn norm_range(s: &str, min: u32, max: u32) -> Option<String> {
    let s = s.trim();
    let num = |p: &str| p.trim().parse::<u32>().ok().filter(|n| (min..=max).contains(n));
    match s.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (num(a)?, num(b)?);
            (a <= b).then(|| if a == b { a.to_string() } else { format!("{a}-{b}") })
        }
        None => num(s).map(|n| n.to_string()),
    }
}

fn truthy(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

impl Dpi {
    /// Check every field and write it in canonical form. The error names the offending field.
    pub fn normalize(self) -> Result<Self> {
        let packets = self.packets.trim().to_lowercase();
        let packets = if packets == "tlshello" {
            packets
        } else {
            norm_range(&packets, 1, 100)
                .ok_or_else(|| Error::msg("DPI packets: use tlshello or a range such as 1-3"))?
        };
        let length = norm_range(&self.length, 1, 65_535)
            .ok_or_else(|| Error::msg("DPI piece size: use a number or a range such as 100-200"))?;
        let interval = norm_range(&self.interval, 0, 60_000)
            .ok_or_else(|| Error::msg("DPI pause: use milliseconds, a number or a range such as 10-20"))?;
        let max_split = match self.max_split.trim() {
            "" => String::new(),
            v => norm_range(v, 0, 65_535)
                .ok_or_else(|| Error::msg("DPI piece limit: use a number or a range such as 100-200"))?,
        };
        Ok(Self {
            packets,
            length,
            interval,
            max_split,
        })
    }

    /// The `fragmentation-*` parameters of a subscription (HTTP headers or `#key: value` lines).
    /// Returns None when the provider does not ask for fragmentation. A value that does not make
    /// sense is replaced by the default one instead of switching the whole thing off.
    pub fn from_params(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        if !get("fragmentation-enable").is_some_and(|v| truthy(&v)) {
            return None;
        }
        let d = Self::default();
        let one = |key: &str, fallback: &str, f: &dyn Fn(&str) -> Option<String>| {
            get(key).and_then(|v| f(&v)).unwrap_or_else(|| fallback.to_string())
        };
        Some(Self {
            packets: one("fragmentation-packets", &d.packets, &|v| {
                let v = v.trim().to_lowercase();
                if v == "tlshello" {
                    Some(v)
                } else {
                    norm_range(&v, 1, 100)
                }
            }),
            length: one("fragmentation-length", &d.length, &|v| norm_range(v, 1, 65_535)),
            interval: one("fragmentation-interval", &d.interval, &|v| norm_range(v, 0, 60_000)),
            max_split: one("fragmentation-maxsplit", "", &|v| norm_range(v, 0, 65_535)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn params(list: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = list.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn happ_example_from_the_docs() {
        let d = Dpi::from_params(params(&[
            ("fragmentation-enable", "1"),
            ("fragmentation-packets", "tlshello"),
            ("fragmentation-length", "50-100"),
            ("fragmentation-interval", "5"),
            ("fragmentation-maxsplit", "100-200"),
        ]))
        .unwrap();
        assert_eq!(
            d,
            Dpi {
                packets: "tlshello".into(),
                length: "50-100".into(),
                interval: "5".into(),
                max_split: "100-200".into()
            }
        );
    }

    #[test]
    fn off_unless_enabled() {
        assert!(Dpi::from_params(params(&[("fragmentation-length", "50-100")])).is_none());
        assert!(Dpi::from_params(params(&[("fragmentation-enable", "0")])).is_none());
        assert!(Dpi::from_params(params(&[("fragmentation-enable", "false")])).is_none());
        let d = Dpi::from_params(params(&[("fragmentation-enable", "true")])).unwrap();
        assert_eq!(d, Dpi::default());
    }

    #[test]
    fn nonsense_values_fall_back_per_field() {
        let d = Dpi::from_params(params(&[
            ("fragmentation-enable", "1"),
            ("fragmentation-length", "0"),
            ("fragmentation-interval", "fast"),
            ("fragmentation-packets", "2-1"),
            ("fragmentation-maxsplit", "9999999"),
        ]))
        .unwrap();
        assert_eq!(d, Dpi::default());
    }

    #[test]
    fn normalize_cleans_and_rejects() {
        let d = Dpi {
            packets: " TLSHello ".into(),
            length: "200-100".into(),
            ..Dpi::default()
        };
        assert!(d.normalize().is_err());
        let d = Dpi {
            length: " 80 - 80 ".into(),
            interval: "0".into(),
            ..Dpi::default()
        };
        let n = d.normalize().unwrap();
        assert_eq!((n.length.as_str(), n.interval.as_str()), ("80", "0"));
        assert!(Dpi { packets: "x".into(), ..Dpi::default() }.normalize().is_err());
        assert_eq!(Dpi { packets: "1-3".into(), ..Dpi::default() }.normalize().unwrap().packets, "1-3");
    }
}
