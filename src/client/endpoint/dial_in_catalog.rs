//! Hub catalog of dial-in machines (`dial-in-machines.json`).
//!
//! Kept separate from `endpoints.json`, which stays strict v1 so older Herdr
//! binaries keep every saved SSH machine. This file tolerates and preserves
//! unknown fields for forward compatibility.

use std::collections::HashSet;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::catalog::store_private_json;
use super::{ProfileId, MAX_LABEL_BYTES};

const DIAL_IN_CATALOG_VERSION: u32 = 1;
pub(crate) const MAX_DIAL_IN_CATALOG_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_DIAL_IN_MACHINES: usize = 64;
const MAX_ID_ATTEMPTS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DialInMachine {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) session: String,
    pub(crate) enabled: bool,
    /// Whether hub clients lend their SSH agent to this machine's link.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) agent_forwarding: bool,
    /// Fields written by newer Herdr versions; preserved on rewrite.
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl DialInMachine {
    /// A new enabled machine with a fresh id. The label is trimmed.
    #[cfg(test)]
    pub(crate) fn new(
        label: impl Into<String>,
        session: impl Into<String>,
    ) -> Result<Self, String> {
        let machine = Self {
            id: ProfileId::generate(),
            label: label.into().trim().to_string(),
            session: session.into(),
            enabled: true,
            agent_forwarding: false,
            extra: serde_json::Map::new(),
        };
        machine.validate()?;
        Ok(machine)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        ProfileId::parse(self.id.to_string())?;
        validate_label(&self.label)?;
        crate::session::validate_name(&self.session)
            .map_err(|error| format!("dial-in machine '{}': {error}", self.label.trim()))
    }

    /// Hub link layout next to the default dial-in catalog.
    pub(crate) fn paths(&self) -> crate::remote::link::LinkPaths {
        crate::remote::link::LinkPaths::for_default_catalog(&self.id)
    }
}

fn validate_label(label: &str) -> Result<(), String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("dial-in machine label cannot be empty".into());
    }
    if label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err(format!(
            "dial-in machine label must be at most {MAX_LABEL_BYTES} bytes and contain no control characters"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DialInCatalog {
    version: u32,
    #[serde(default)]
    pub(crate) machines: Vec<DialInMachine>,
    /// Fields written by newer Herdr versions; preserved on rewrite.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Default for DialInCatalog {
    fn default() -> Self {
        Self {
            version: DIAL_IN_CATALOG_VERSION,
            machines: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

impl DialInCatalog {
    /// Loads the default catalog; a missing file is an empty catalog.
    pub(crate) fn load() -> Result<Self, String> {
        Self::load_from_path(&dial_in_catalog_path())
    }

    /// Loads `path`; a missing file is an empty catalog.
    pub(crate) fn load_from_path(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(format!(
                    "failed to open dial-in machine catalog {}: {error}",
                    path.display()
                ))
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect dial-in machine catalog: {error}"))?;
        if metadata.len() > MAX_DIAL_IN_CATALOG_BYTES {
            return Err("dial-in machine catalog exceeds the storage limit".into());
        }
        let mut content = String::new();
        file.take(MAX_DIAL_IN_CATALOG_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("failed to read dial-in machine catalog: {error}"))?;
        if content.len() as u64 > MAX_DIAL_IN_CATALOG_BYTES {
            return Err("dial-in machine catalog exceeds the storage limit".into());
        }
        let catalog: Self = serde_json::from_str(&content)
            .map_err(|error| format!("stored dial-in machine catalog is invalid: {error}"))?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Like [`Self::load_from_path`], but refuses a file that is a symlink,
    /// not owned by the effective user, or writable by group or others. For
    /// the hub acceptor, which runs under sshd's forced command.
    pub(crate) fn load_from_trusted_path(path: &Path) -> Result<Self, String> {
        match crate::platform::file_is_private_to_current_user(path) {
            Ok(true) => Self::load_from_path(path),
            Ok(false) => Err(format!(
                "refusing dial-in machine catalog {}: it must be a regular file owned by the current user and not writable by others",
                path.display()
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!(
                "failed to inspect dial-in machine catalog {}: {error}",
                path.display()
            )),
        }
    }

    pub(crate) fn store(&self) -> Result<(), String> {
        self.store_to_path(&dial_in_catalog_path())
    }

    pub(crate) fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to encode dial-in machine catalog: {error}"))?;
        store_private_json(path, &content, "dial-in machine catalog")
    }

    /// Adds an enabled machine. Its id is regenerated until it collides with
    /// neither this catalog (including link directory prefixes) nor
    /// `taken_ids` (for example saved SSH profile ids).
    pub(crate) fn add(
        &mut self,
        label: impl Into<String>,
        session: impl Into<String>,
        taken_ids: &[ProfileId],
    ) -> Result<ProfileId, String> {
        self.add_with_id_source(label, session, taken_ids, ProfileId::generate)
    }

    fn add_with_id_source(
        &mut self,
        label: impl Into<String>,
        session: impl Into<String>,
        taken_ids: &[ProfileId],
        mut next_id: impl FnMut() -> ProfileId,
    ) -> Result<ProfileId, String> {
        if self.machines.len() >= MAX_DIAL_IN_MACHINES {
            return Err(format!(
                "at most {MAX_DIAL_IN_MACHINES} dial-in machines can be saved"
            ));
        }
        let mut machine = DialInMachine {
            id: next_id(),
            label: label.into().trim().to_string(),
            session: session.into(),
            enabled: true,
            agent_forwarding: false,
            extra: serde_json::Map::new(),
        };
        machine.validate()?;
        if self.find_by_label(&machine.label).is_some() {
            return Err(format!(
                "a dial-in machine labeled '{}' already exists",
                machine.label
            ));
        }
        let mut attempts = 0;
        while self.id_is_taken(&machine.id, taken_ids) {
            attempts += 1;
            if attempts >= MAX_ID_ATTEMPTS {
                return Err("failed to generate a unique dial-in machine id".into());
            }
            machine.id = next_id();
        }
        let id = machine.id.clone();
        self.machines.push(machine);
        Ok(id)
    }

    fn id_is_taken(&self, id: &ProfileId, taken_ids: &[ProfileId]) -> bool {
        let link_dir = crate::remote::link::link_dir_name(id);
        taken_ids.contains(id)
            || self.machines.iter().any(|machine| {
                machine.id == *id || crate::remote::link::link_dir_name(&machine.id) == link_dir
            })
    }

    pub(crate) fn get(&self, id: &ProfileId) -> Option<&DialInMachine> {
        self.machines.iter().find(|machine| &machine.id == id)
    }

    /// The machine whose (trimmed) label equals `label`, case-sensitively.
    pub(crate) fn find_by_label(&self, label: &str) -> Option<&DialInMachine> {
        let label = label.trim();
        self.machines
            .iter()
            .find(|machine| machine.label.trim() == label)
    }

    /// Renames `id`; `Ok(false)` when it does not exist. The label is trimmed
    /// and must stay unique within the catalog.
    pub(crate) fn rename(
        &mut self,
        id: &ProfileId,
        label: impl Into<String>,
    ) -> Result<bool, String> {
        let Some(index) = self.machines.iter().position(|machine| &machine.id == id) else {
            return Ok(false);
        };
        let label = label.into().trim().to_string();
        validate_label(&label)?;
        if self
            .machines
            .iter()
            .any(|machine| &machine.id != id && machine.label.trim() == label)
        {
            return Err(format!(
                "a dial-in machine labeled '{label}' already exists"
            ));
        }
        self.machines[index].label = label;
        Ok(true)
    }

    pub(crate) fn set_enabled(&mut self, id: &ProfileId, enabled: bool) -> bool {
        let Some(machine) = self.machines.iter_mut().find(|machine| &machine.id == id) else {
            return false;
        };
        machine.enabled = enabled;
        true
    }

    /// Sets agent forwarding for `id`; false when it does not exist.
    pub(crate) fn set_agent_forwarding(&mut self, id: &ProfileId, enabled: bool) -> bool {
        let Some(machine) = self.machines.iter_mut().find(|machine| &machine.id == id) else {
            return false;
        };
        machine.agent_forwarding = enabled;
        true
    }

    pub(crate) fn remove(&mut self, id: &ProfileId) -> bool {
        let previous_len = self.machines.len();
        self.machines.retain(|machine| &machine.id != id);
        self.machines.len() != previous_len
    }

    #[cfg(test)]
    pub(crate) fn has_enabled(&self) -> bool {
        self.machines.iter().any(|machine| machine.enabled)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != DIAL_IN_CATALOG_VERSION {
            return Err(format!(
                "unsupported dial-in machine catalog version {}; expected {DIAL_IN_CATALOG_VERSION}",
                self.version
            ));
        }
        if self.machines.len() > MAX_DIAL_IN_MACHINES {
            return Err(format!(
                "dial-in machine catalog contains more than {MAX_DIAL_IN_MACHINES} machines"
            ));
        }
        let mut ids = HashSet::new();
        let mut link_dirs = HashSet::new();
        let mut labels = HashSet::new();
        for machine in &self.machines {
            machine.validate()?;
            if !ids.insert(machine.id.clone()) {
                return Err(format!("duplicate dial-in machine id {}", machine.id));
            }
            if !link_dirs.insert(crate::remote::link::link_dir_name(&machine.id).to_string()) {
                return Err(format!(
                    "dial-in machine id {} shares its link directory prefix with another machine",
                    machine.id
                ));
            }
            if !labels.insert(machine.label.trim().to_string()) {
                return Err(format!(
                    "duplicate dial-in machine label '{}'",
                    machine.label.trim()
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn dial_in_catalog_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("dial-in-machines.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "herdr-dial-in-catalog-{}-{name}",
                std::process::id()
            ))
            .join("dial-in-machines.json")
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn catalog_round_trips_and_missing_file_is_empty() {
        let path = path("roundtrip");
        cleanup(&path);
        assert_eq!(
            DialInCatalog::load_from_path(&path).unwrap(),
            DialInCatalog::default()
        );
        let mut catalog = DialInCatalog::default();
        let first = catalog.add("  Laptop ", "default", &[]).unwrap();
        let second = catalog.add("Build box", "work", &[]).unwrap();
        assert!(catalog.set_enabled(&second, false));
        catalog.store_to_path(&path).unwrap();
        let loaded = DialInCatalog::load_from_path(&path).unwrap();
        assert_eq!(loaded, catalog);
        assert_eq!(loaded.get(&first).unwrap().label, "Laptop");
        assert!(!loaded.get(&second).unwrap().enabled);
        assert!(loaded.has_enabled());
        assert_eq!(
            loaded.find_by_label("Build box").map(|machine| &machine.id),
            Some(&second)
        );
        assert!(loaded.find_by_label("build box").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            assert_eq!(
                DialInCatalog::load_from_trusted_path(&path).unwrap(),
                catalog
            );
        }
        cleanup(&path);
    }

    #[test]
    fn unknown_fields_are_preserved_on_rewrite() {
        let path = path("unknown");
        cleanup(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{
  "version": 1,
  "future_top": {"nested": [1, 2]},
  "machines": [
    {
      "id": "0123456789abcdef0123456789abcdef",
      "label": "Laptop",
      "session": "default",
      "enabled": true,
      "transport_hint": "relay",
      "added_at_ms": 5
    }
  ]
}"#,
        )
        .unwrap();
        let mut catalog = DialInCatalog::load_from_path(&path).unwrap();
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            catalog.get(&id).unwrap().extra.get("transport_hint"),
            Some(&serde_json::json!("relay"))
        );
        assert!(catalog.rename(&id, "Renamed").unwrap());
        catalog.store_to_path(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["future_top"], serde_json::json!({"nested": [1, 2]}));
        assert_eq!(value["machines"][0]["transport_hint"], "relay");
        assert_eq!(value["machines"][0]["added_at_ms"], 5);
        assert_eq!(value["machines"][0]["label"], "Renamed");
        cleanup(&path);
    }

    #[test]
    fn agent_forwarding_is_an_explicit_optional_field() {
        let path = path("agent");
        cleanup(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Files written before the field existed load with it off.
        std::fs::write(
            &path,
            r#"{"version":1,"machines":[{"id":"0123456789abcdef0123456789abcdef","label":"Laptop","session":"default","enabled":true}]}"#,
        )
        .unwrap();
        let mut catalog = DialInCatalog::load_from_path(&path).unwrap();
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert!(!catalog.get(&id).unwrap().agent_forwarding);

        assert!(catalog.set_agent_forwarding(&id, true));
        catalog.store_to_path(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["machines"][0]["agent_forwarding"], true);
        let loaded = DialInCatalog::load_from_path(&path).unwrap();
        let machine = loaded.get(&id).unwrap();
        assert!(machine.agent_forwarding);
        assert!(!machine.extra.contains_key("agent_forwarding"));

        assert!(catalog.set_agent_forwarding(&id, false));
        catalog.store_to_path(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(value["machines"][0].get("agent_forwarding").is_none());
        let missing = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
        assert!(!catalog.set_agent_forwarding(&missing, true));
        cleanup(&path);
    }

    #[test]
    fn catalog_validation_rejects_bad_content() {
        let id = "0123456789abcdef0123456789abcdef";
        let same_prefix = "0123456789abffffffffffffffffffff";
        let machine = |id: &str, label: &str, session: &str| serde_json::json!({"id": id, "label": label, "session": session, "enabled": true});
        let cases = [
            serde_json::json!({"version": 2, "machines": []}),
            serde_json::json!({"machines": []}),
            serde_json::json!({"version": 1, "machines": [machine("XYZ", "a", "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "  ", "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a\u{7}b", "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, &"x".repeat(MAX_LABEL_BYTES + 1), "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a", "bad name")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a", "")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a", "default"), machine(id, "b", "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a", "default"), machine(same_prefix, "b", "default")]}),
            serde_json::json!({"version": 1, "machines": [machine(id, "a", "default"), machine("fedcba9876543210fedcba9876543210", " a ", "default")]}),
            serde_json::json!({"version": 1, "machines": [{"id": id, "label": "a", "session": "default"}]}),
        ];
        for (index, case) in cases.iter().enumerate() {
            let path = path(&format!("invalid-{index}"));
            cleanup(&path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, serde_json::to_vec(case).unwrap()).unwrap();
            assert!(
                DialInCatalog::load_from_path(&path).is_err(),
                "case {index} should be rejected: {case}"
            );
            cleanup(&path);
        }
    }

    #[test]
    fn catalog_enforces_size_and_count_limits() {
        let path = path("oversized");
        cleanup(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut content = br#"{"version":1,"machines":[]}"#.to_vec();
        content.resize(MAX_DIAL_IN_CATALOG_BYTES as usize + 1, b' ');
        std::fs::write(&path, content).unwrap();
        assert!(DialInCatalog::load_from_path(&path)
            .unwrap_err()
            .contains("storage limit"));
        cleanup(&path);

        let mut catalog = DialInCatalog::default();
        for index in 0..MAX_DIAL_IN_MACHINES {
            catalog
                .add(format!("machine {index}"), "default", &[])
                .unwrap();
        }
        assert!(catalog.add("one too many", "default", &[]).is_err());
        assert_eq!(catalog.machines.len(), MAX_DIAL_IN_MACHINES);
    }

    #[test]
    fn labels_must_stay_unique_and_valid() {
        let mut catalog = DialInCatalog::default();
        let first = catalog.add("Laptop", "default", &[]).unwrap();
        let second = catalog.add("Desktop", "default", &[]).unwrap();
        assert!(catalog.add(" Laptop ", "default", &[]).is_err());
        assert!(catalog.add("Box", "not valid", &[]).is_err());
        assert!(catalog.add("", "default", &[]).is_err());
        assert!(catalog.rename(&second, "Laptop").is_err());
        assert!(catalog.rename(&second, "\u{1b}[2J").is_err());
        assert!(catalog.rename(&first, " Laptop ").unwrap());
        assert_eq!(catalog.get(&first).unwrap().label, "Laptop");
        let missing = ProfileId::parse("ffffffffffffffffffffffffffffffff").unwrap();
        assert!(!catalog.rename(&missing, "Other").unwrap());
        assert!(!catalog.set_enabled(&missing, false));
        assert!(!catalog.remove(&missing));
        assert!(catalog.remove(&first));
        assert!(catalog.get(&first).is_none());
        assert!(catalog.set_enabled(&second, false));
        assert!(!catalog.has_enabled());
        assert_eq!(catalog.machines.len(), 1);
    }

    #[test]
    fn add_regenerates_ids_that_collide_with_taken_ids_or_link_prefixes() {
        let existing = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let same_prefix = ProfileId::parse("0123456789ab00000000000000000000").unwrap();
        let ssh_id = ProfileId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let fresh = ProfileId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let catalog_with_existing = || {
            let mut catalog = DialInCatalog::default();
            catalog.machines.push(DialInMachine {
                id: existing.clone(),
                ..DialInMachine::new("Existing", "default").unwrap()
            });
            catalog
        };

        let mut catalog = catalog_with_existing();
        let mut script = vec![
            fresh.clone(),
            same_prefix.clone(),
            ssh_id.clone(),
            existing.clone(),
        ];
        let mut draws = 0;
        let id = catalog
            .add_with_id_source("New", "default", std::slice::from_ref(&ssh_id), || {
                draws += 1;
                script.pop().expect("id source exhausted")
            })
            .unwrap();
        assert_eq!(id, fresh);
        assert_eq!(draws, 4);
        assert_eq!(catalog.get(&fresh).unwrap().label, "New");

        let mut exhausted = catalog_with_existing();
        let error = exhausted
            .add_with_id_source("Never", "default", &[], || existing.clone())
            .unwrap_err();
        assert!(error.contains("unique"), "{error}");
        assert_eq!(exhausted.machines.len(), 1);
    }

    #[test]
    fn machine_paths_use_the_default_catalog_directory() {
        let machine = DialInMachine::new("Laptop", "default").unwrap();
        let paths = machine.paths();
        assert_eq!(
            paths.dir,
            dial_in_catalog_path()
                .parent()
                .unwrap()
                .join("links")
                .join(&machine.id.as_str()[..12])
        );
    }
}
