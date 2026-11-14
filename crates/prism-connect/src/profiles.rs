use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    dpi::Dpi,
    error::{Error, Result},
    paths::Paths,
    subscription::{Source, SubMeta, Usage},
    util::write_atomic,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub id: String,
    pub name: String,
    /// Some => remote subscription, None => local profile.
    pub url: Option<String>,
    pub source: Source,
    pub nodes: usize,
    pub updated_at: Option<String>,
    /// 0 = manual updates only.
    pub interval_hours: u32,
    pub usage: Option<Usage>,
    /// The provider's announcement (`announce`), at most 200 characters.
    #[serde(default)]
    pub announce: Option<String>,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    /// DPI-bypass instruction of the provider (`fragmentation-*`).
    #[serde(default)]
    pub dpi: Option<Dpi>,
    /// The provider limits devices (`x-hwid-active`): this PC's id was sent and counts.
    #[serde(default)]
    pub hwid_active: bool,
    /// The name the provider gave the subscription (`profile-title`).
    #[serde(default)]
    pub remote_title: Option<String>,
    /// The provider's remote tests (`kometfy-tasks`, `kometfy-reports`).
    #[serde(default)]
    pub tasks_url: Option<String>,
    #[serde(default)]
    pub reports_url: Option<String>,
    /// The user chose the name: a rename on the provider's side no longer replaces it.
    /// A profile saved by an older version has no such field, and its name may well be the
    /// user's own, so a missing value means "custom".
    #[serde(default = "name_is_custom")]
    pub name_custom: bool,
}

fn name_is_custom() -> bool {
    true
}

impl ProfileMeta {
    /// Take over what the provider said in the last answer. The title replaces the name unless the
    /// user picked their own; everything else simply follows the provider (a missing header means
    /// the provider dropped it).
    pub fn apply_meta(&mut self, m: SubMeta, title: Option<String>) {
        self.announce = m.announce;
        self.support_url = m.support_url;
        self.web_url = m.web_url;
        self.dpi = m.dpi;
        self.hwid_active = m.hwid_active;
        self.tasks_url = m.tasks_url;
        self.reports_url = m.reports_url;
        if let Some(t) = title {
            if !self.name_custom {
                self.name = t.clone();
            }
            self.remote_title = Some(t);
        }
    }
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_string()
}

pub struct ProfileStore {
    paths: Paths,
    items: Vec<ProfileMeta>,
}

impl ProfileStore {
    pub fn load(paths: &Paths) -> Self {
        let mut items: Vec<ProfileMeta> = fs::read_to_string(paths.profiles_index())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        items.retain(|p| paths.profiles_dir().join(format!("{}.yaml", p.id)).exists());
        Self {
            paths: paths.clone(),
            items,
        }
    }

    pub fn items(&self) -> &[ProfileMeta] {
        &self.items
    }

    pub fn get(&self, id: &str) -> Option<&ProfileMeta> {
        self.items.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut ProfileMeta> {
        self.items.iter_mut().find(|p| p.id == id)
    }

    /// Only ids already in the index reach the filesystem (no path traversal).
    fn file(&self, id: &str) -> Result<PathBuf> {
        self.get(id)
            .map(|p| self.paths.profiles_dir().join(format!("{}.yaml", p.id)))
            .ok_or_else(|| Error::msg("profile not found"))
    }

    pub fn read(&self, id: &str) -> Result<String> {
        Ok(fs::read_to_string(self.file(id)?)?)
    }

    pub fn add(&mut self, meta: ProfileMeta, yaml: &str) -> Result<()> {
        let path = self.paths.profiles_dir().join(format!("{}.yaml", meta.id));
        write_atomic(&path, yaml.as_bytes())?;
        self.items.push(meta);
        self.save_index()
    }

    pub fn write(&mut self, id: &str, yaml: &str) -> Result<()> {
        write_atomic(&self.file(id)?, yaml.as_bytes())?;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        let path = self.file(id)?;
        let _ = fs::remove_file(path);
        self.items.retain(|p| p.id != id);
        self.save_index()
    }

    pub fn save_index(&self) -> Result<()> {
        write_atomic(
            &self.paths.profiles_index(),
            serde_json::to_string_pretty(&self.items)?.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, custom: bool) -> ProfileMeta {
        ProfileMeta {
            id: "a".into(),
            name: name.into(),
            url: Some("https://sub.example.com/x".into()),
            source: Source::Clash,
            nodes: 1,
            updated_at: None,
            interval_hours: 24,
            usage: None,
            announce: None,
            support_url: None,
            web_url: None,
            dpi: None,
            hwid_active: false,
            tasks_url: None,
            reports_url: None,
            remote_title: None,
            name_custom: custom,
        }
    }

    #[test]
    fn a_rename_on_the_provider_side_follows_unless_the_user_chose_a_name() {
        let mut auto = meta("Old title", false);
        auto.apply_meta(SubMeta::default(), Some("New title".into()));
        assert_eq!((auto.name.as_str(), auto.remote_title.as_deref()), ("New title", Some("New title")));

        let mut mine = meta("My servers", true);
        mine.apply_meta(SubMeta::default(), Some("New title".into()));
        assert_eq!(mine.name, "My servers");
        assert_eq!(mine.remote_title.as_deref(), Some("New title"), "kept, so the name can be reset to it");

        let mut silent = meta("Kept", false);
        silent.apply_meta(SubMeta::default(), None);
        assert_eq!(silent.name, "Kept", "no title in the answer: the name stays");
    }

    #[test]
    fn what_the_provider_dropped_is_dropped() {
        let mut p = meta("P", false);
        p.apply_meta(
            SubMeta {
                announce: Some("Maintenance tonight".into()),
                dpi: Some(Dpi::default()),
                hwid_active: true,
                ..Default::default()
            },
            None,
        );
        assert!(p.announce.is_some() && p.dpi.is_some() && p.hwid_active);
        p.apply_meta(SubMeta::default(), None);
        assert!(p.announce.is_none() && p.dpi.is_none() && !p.hwid_active);
    }

    #[test]
    fn a_profile_saved_by_an_older_version_keeps_its_name() {
        let old = r#"{"id":"a","name":"My name","url":"https://x","source":"clash","nodes":3,"updated_at":null,"interval_hours":24,"usage":null}"#;
        let mut p: ProfileMeta = serde_json::from_str(old).unwrap();
        assert!(p.name_custom && p.announce.is_none() && !p.hwid_active);
        p.apply_meta(SubMeta::default(), Some("Provider".into()));
        assert_eq!(p.name, "My name");
    }
}
