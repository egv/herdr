use std::collections::HashSet;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::{dial_in_catalog_path, DialInCatalog, DialInMachine, ProfileId, ViaMachine};

const CATALOG_VERSION: u32 = 1;
const SELECTION_VERSION: u32 = 1;
const MAX_CATALOG_BYTES: u64 = 64 * 1024;
const MAX_PROFILES: usize = 64;
pub(crate) const MAX_LABEL_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 1024;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSshEndpoint {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) target: String,
    pub(crate) session: String,
    pub(crate) enabled: bool,
}

impl SavedSshEndpoint {
    pub(crate) fn new(
        label: impl Into<String>,
        target: impl Into<String>,
        session: impl Into<String>,
    ) -> Result<Self, String> {
        let profile = Self {
            id: ProfileId::generate(),
            label: label.into(),
            target: target.into(),
            session: session.into(),
            enabled: true,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), String> {
        ProfileId::parse(self.id.to_string())?;
        let label = self.label.trim();
        if label.is_empty() {
            return Err("SSH endpoint label cannot be empty".into());
        }
        if label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
            return Err(format!(
                "SSH endpoint label must be at most {MAX_LABEL_BYTES} bytes and contain no control characters"
            ));
        }
        if self.target.len() > MAX_TARGET_BYTES || self.target.chars().any(char::is_control) {
            return Err(format!(
                "SSH target must be at most {MAX_TARGET_BYTES} bytes and contain no control characters"
            ));
        }
        crate::remote::validate_remote_target(&self.target).map(|_| ())?;
        let authority = self.target.strip_prefix("ssh://").unwrap_or(&self.target);
        if authority
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
        {
            return Err("SSH target must not contain a password".into());
        }
        crate::session::validate_name(&self.session)?;
        Ok(())
    }
}

/// How a saved machine is reached. Saved machines share one id space
/// ([`ProfileId`]) across catalogs, so the kind is a property of the catalog
/// the machine was loaded from, not of its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SavedMachineKind {
    /// Reached by this client over SSH (`endpoints.json`).
    Ssh,
    /// Reaches this hub by dialing in (`dial-in-machines.json`).
    DialIn,
    /// A dial-in machine of a relay hub, reached through that hub.
    Via,
}

/// Catalog-neutral facts about one saved machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SavedMachineSummary {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) enabled: bool,
    pub(crate) kind: SavedMachineKind,
}

impl From<&SavedSshEndpoint> for SavedMachineSummary {
    fn from(profile: &SavedSshEndpoint) -> Self {
        Self {
            id: profile.id.clone(),
            label: profile.label.clone(),
            enabled: profile.enabled,
            kind: SavedMachineKind::Ssh,
        }
    }
}

impl From<&DialInMachine> for SavedMachineSummary {
    fn from(machine: &DialInMachine) -> Self {
        Self {
            id: machine.id.clone(),
            label: machine.label.clone(),
            enabled: machine.enabled,
            kind: SavedMachineKind::DialIn,
        }
    }
}

impl From<&ViaMachine> for SavedMachineSummary {
    fn from(machine: &ViaMachine) -> Self {
        Self {
            id: machine.id.clone(),
            label: machine.display_label(),
            enabled: true,
            kind: SavedMachineKind::Via,
        }
    }
}

/// SSH machines first, then dial-in machines, each in catalog order.
pub(crate) fn saved_machine_summaries(
    ssh: &[SavedSshEndpoint],
    dial_in: &[DialInMachine],
) -> Vec<SavedMachineSummary> {
    ssh.iter()
        .map(SavedMachineSummary::from)
        .chain(dial_in.iter().map(SavedMachineSummary::from))
        .collect()
}

/// Drops dial-in machines whose id is also a saved SSH profile id. Ids are
/// generated unique across both catalogs, so a collision means a hand-edited
/// file; the SSH profile keeps the identity.
pub(crate) fn dial_in_without_id_collisions(
    ssh: &[SavedSshEndpoint],
    dial_in: Vec<DialInMachine>,
) -> Vec<DialInMachine> {
    dial_in
        .into_iter()
        .filter(|machine| {
            let collides = ssh.iter().any(|profile| profile.id == machine.id);
            if collides {
                tracing::warn!(
                    id = %machine.id,
                    "ignoring dial-in machine whose id is also a saved SSH machine"
                );
            }
            !collides
        })
        .collect()
}

/// Saved machines and this client's selection.
///
/// `endpoints.json` stays byte-compatible strict v1 (`deny_unknown_fields`) so
/// older Herdr binaries keep every SSH machine. Dial-in machines live here only
/// in memory and are persisted by [`DialInCatalog`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointCatalog {
    version: u32,
    /// In memory and in the selection file this may name an enabled SSH or
    /// dial-in machine; `endpoints.json` only ever records an SSH selection.
    #[serde(default)]
    pub(crate) selected_profile: Option<ProfileId>,
    #[serde(default)]
    pub(crate) ssh: Vec<SavedSshEndpoint>,
    #[serde(skip)]
    pub(crate) dial_in: Vec<DialInMachine>,
    /// Machines reached through relay hubs, as last listed by them.
    #[serde(skip)]
    pub(crate) via: Vec<ViaMachine>,
    /// Whether an enabled relay hub is saved, which makes this client federated.
    #[serde(skip)]
    pub(crate) relays_enabled: bool,
    /// A stored selection naming no known machine yet: a relay may list it.
    #[serde(skip)]
    pub(crate) pending_selection: Option<ProfileId>,
}

/// The exact v1 `endpoints.json` shape.
#[derive(Serialize)]
struct StoredEndpointCatalog<'a> {
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_profile: Option<&'a ProfileId>,
    ssh: &'a [SavedSshEndpoint],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSelection {
    version: u32,
    selected_profile: Option<ProfileId>,
}

impl Default for EndpointCatalog {
    fn default() -> Self {
        Self {
            version: CATALOG_VERSION,
            selected_profile: None,
            ssh: Vec::new(),
            dial_in: Vec::new(),
            via: Vec::new(),
            relays_enabled: false,
            pending_selection: None,
        }
    }
}

impl EndpointCatalog {
    /// Loads saved SSH machines, dial-in machines and this client's selection.
    /// An unusable dial-in catalog never prevents loading SSH machines.
    pub(crate) fn load() -> Result<Self, String> {
        let mut catalog =
            Self::load_from_paths(&catalog_path(), &dial_in_catalog_path(), &selection_path())?;
        catalog.set_relays_enabled(
            super::RelayCatalog::load()
                .inspect_err(|error| tracing::warn!(%error, "saved relay hubs are unavailable"))
                .is_ok_and(|relays| relays.enabled().next().is_some()),
        );
        Ok(catalog)
    }

    /// With an enabled relay hub, a selection naming no known machine yet
    /// may be a via machine that a relay lists later: it waits, and wins
    /// over the SSH selection that `endpoints.json` keeps for older Herdr.
    fn set_relays_enabled(&mut self, enabled: bool) {
        self.relays_enabled = enabled;
        if !enabled {
            self.pending_selection = None;
        } else if self.pending_selection.is_some() {
            self.selected_profile = None;
        }
    }

    pub(crate) fn load_profiles() -> Result<Vec<SavedSshEndpoint>, String> {
        // Live clients keep their own selection, independent of other attached clients.
        Self::load_from_path(&catalog_path()).map(|catalog| catalog.ssh)
    }

    pub(crate) fn load_dial_in_machines() -> Result<Vec<DialInMachine>, String> {
        DialInCatalog::load().map(|catalog| catalog.machines)
    }

    fn load_from_paths(
        catalog_path: &Path,
        dial_in_path: &Path,
        selection_path: &Path,
    ) -> Result<Self, String> {
        let mut catalog = Self::load_from_path(catalog_path)?;
        let dial_in = DialInCatalog::load_from_path(dial_in_path)
            .map(|dial_in| dial_in.machines)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    %error,
                    path = %dial_in_path.display(),
                    "saved dial-in machines are unavailable; keeping SSH machines"
                );
                Vec::new()
            });
        catalog.dial_in = dial_in_without_id_collisions(&catalog.ssh, dial_in);
        match load_selection_from_path(selection_path) {
            Ok(Some(selection)) => {
                let valid = selection
                    .selected_profile
                    .as_ref()
                    .is_none_or(|selected| catalog.machine_is_enabled(selected));
                if valid {
                    catalog.selected_profile = selection.selected_profile;
                } else {
                    catalog.pending_selection = selection.selected_profile;
                    tracing::warn!(
                        path = %selection_path.display(),
                        "saved endpoint selection is absent or disabled; using Local"
                    );
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %selection_path.display(),
                    "saved endpoint selection is unavailable; using Local"
                );
            }
        }
        Ok(catalog)
    }

    pub(crate) fn store_profiles(&self) -> Result<(), String> {
        self.store_to_path(&catalog_path())
    }

    pub(crate) fn store_selection(&self) -> Result<(), String> {
        self.store_selection_to_path(&selection_path())
    }

    fn store_selection_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(&EndpointSelection {
            version: SELECTION_VERSION,
            selected_profile: self.selected_profile.clone(),
        })
        .map_err(|error| format!("failed to encode endpoint selection: {error}"))?;
        store_private_json(path, &content, "endpoint selection")
    }

    pub(crate) fn add_ssh(
        &mut self,
        label: impl Into<String>,
        target: impl Into<String>,
        session: impl Into<String>,
    ) -> Result<ProfileId, String> {
        if self.ssh.len() >= MAX_PROFILES {
            return Err(format!("at most {MAX_PROFILES} SSH endpoints can be saved"));
        }
        let profile = SavedSshEndpoint::new(label, target, session)?;
        let id = profile.id.clone();
        self.ssh.push(profile);
        Ok(id)
    }

    pub(crate) fn rename_ssh(
        &mut self,
        id: &ProfileId,
        label: impl Into<String>,
    ) -> Result<bool, String> {
        let Some(index) = self.ssh.iter().position(|profile| &profile.id == id) else {
            return Ok(false);
        };
        let mut renamed = self.ssh[index].clone();
        renamed.label = label.into();
        renamed.validate()?;
        self.ssh[index] = renamed;
        Ok(true)
    }

    pub(crate) fn remove_ssh(&mut self, id: &ProfileId) -> bool {
        let previous_len = self.ssh.len();
        self.ssh.retain(|profile| &profile.id != id);
        if self.selected_profile.as_ref() == Some(id) {
            self.selected_profile = None;
        }
        self.ssh.len() != previous_len
    }

    pub(crate) fn select_local(&mut self) {
        self.selected_profile = None;
        self.pending_selection = None;
    }

    pub(crate) fn select_endpoint(&mut self, endpoint_id: &super::ClientEndpointId) -> bool {
        match endpoint_id {
            super::ClientEndpointId::Local => {
                self.select_local();
                true
            }
            super::ClientEndpointId::Ssh(profile_id) => self.select_ssh(profile_id),
        }
    }

    /// Selects an enabled saved machine (SSH or dial-in) by id.
    pub(crate) fn select_ssh(&mut self, id: &ProfileId) -> bool {
        if !self.machine_is_enabled(id) {
            return false;
        }
        self.selected_profile = Some(id.clone());
        self.pending_selection = None;
        true
    }

    /// Whether `id` names an enabled saved machine in either catalog, or a
    /// machine a relay hub lists.
    pub(crate) fn machine_is_enabled(&self, id: &ProfileId) -> bool {
        self.ssh_is_enabled(id)
            || self
                .dial_in
                .iter()
                .any(|machine| &machine.id == id && machine.enabled)
            || self.via.iter().any(|machine| &machine.id == id)
    }

    fn ssh_is_enabled(&self, id: &ProfileId) -> bool {
        self.ssh
            .iter()
            .any(|profile| &profile.id == id && profile.enabled)
    }

    pub(crate) fn has_enabled_ssh(&self) -> bool {
        self.ssh.iter().any(|profile| profile.enabled)
    }

    /// Whether any saved machine (SSH or dial-in) is enabled, which makes
    /// this client federated.
    pub(crate) fn has_enabled_machines(&self) -> bool {
        self.has_enabled_ssh()
            || self.dial_in.iter().any(|machine| machine.enabled)
            || self.relays_enabled
            || !self.via.is_empty()
    }

    /// SSH, dial-in, then via machines.
    pub(crate) fn machine_summaries(&self) -> Vec<SavedMachineSummary> {
        let mut summaries = saved_machine_summaries(&self.ssh, &self.dial_in);
        summaries.extend(self.via.iter().map(SavedMachineSummary::from));
        summaries
    }

    pub(crate) fn contains_enabled_target_session(&self, target: &str, session: &str) -> bool {
        self.ssh.iter().any(|profile| {
            profile.enabled && profile.target == target && profile.session == session
        })
    }

    pub(crate) fn set_enabled(&mut self, id: &ProfileId, enabled: bool) -> bool {
        let Some(profile) = self.ssh.iter_mut().find(|profile| &profile.id == id) else {
            return false;
        };
        profile.enabled = enabled;
        if !enabled && self.selected_profile.as_ref() == Some(id) {
            self.selected_profile = None;
        }
        true
    }

    /// Validates the in-memory catalog: the selection may name an enabled SSH
    /// or dial-in machine.
    fn validate(&self) -> Result<(), String> {
        self.validate_profiles()?;
        if self
            .selected_profile
            .as_ref()
            .is_some_and(|selected| !self.machine_is_enabled(selected))
        {
            return Err("selected machine is absent or disabled in the catalog".into());
        }
        Ok(())
    }

    /// The strict v1 rules for `endpoints.json`, unchanged so files written by
    /// this version load in older binaries and vice versa.
    fn validate_stored(&self) -> Result<(), String> {
        self.validate_profiles()?;
        if self
            .selected_profile
            .as_ref()
            .is_some_and(|selected| !self.ssh_is_enabled(selected))
        {
            return Err("selected SSH endpoint is absent or disabled in the catalog".into());
        }
        Ok(())
    }

    fn validate_profiles(&self) -> Result<(), String> {
        if self.version != CATALOG_VERSION {
            return Err(format!(
                "unsupported endpoint catalog version {}; expected {CATALOG_VERSION}",
                self.version
            ));
        }
        if self.ssh.len() > MAX_PROFILES {
            return Err(format!(
                "endpoint catalog contains more than {MAX_PROFILES} SSH profiles"
            ));
        }
        let mut ids = HashSet::new();
        for profile in &self.ssh {
            profile.validate()?;
            if !ids.insert(profile.id.clone()) {
                return Err(format!("duplicate endpoint profile id {}", profile.id));
            }
        }
        Ok(())
    }

    fn load_from_path(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(format!(
                    "failed to open endpoint catalog {}: {error}",
                    path.display()
                ))
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect endpoint catalog: {error}"))?;
        if metadata.len() > MAX_CATALOG_BYTES {
            return Err("endpoint catalog exceeds the storage limit".into());
        }
        let mut content = String::new();
        file.take(MAX_CATALOG_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("failed to read endpoint catalog: {error}"))?;
        if content.len() as u64 > MAX_CATALOG_BYTES {
            return Err("endpoint catalog exceeds the storage limit".into());
        }
        let catalog: Self = serde_json::from_str(&content)
            .map_err(|error| format!("stored endpoint catalog is invalid: {error}"))?;
        catalog.validate_stored()?;
        Ok(catalog)
    }

    fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        // Older binaries reject `endpoints.json` wholesale when its selection is
        // not an enabled SSH profile, so a dial-in selection must never leak here.
        let stored = StoredEndpointCatalog {
            version: self.version,
            selected_profile: self
                .selected_profile
                .as_ref()
                .filter(|selected| self.ssh_is_enabled(selected)),
            ssh: &self.ssh,
        };
        let content = serde_json::to_vec_pretty(&stored)
            .map_err(|error| format!("failed to encode endpoint catalog: {error}"))?;
        store_private_json(path, &content, "endpoint catalog")
    }
}

fn load_selection_from_path(path: &Path) -> Result<Option<EndpointSelection>, String> {
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read endpoint selection: {error}")),
    };
    if content.len() as u64 > MAX_CATALOG_BYTES {
        return Err("endpoint selection exceeds the storage limit".into());
    }
    let selection: EndpointSelection = serde_json::from_slice(&content)
        .map_err(|error| format!("stored endpoint selection is invalid: {error}"))?;
    if selection.version != SELECTION_VERSION {
        return Err(format!(
            "unsupported endpoint selection version {}; expected {SELECTION_VERSION}",
            selection.version
        ));
    }
    Ok(Some(selection))
}

pub(super) fn store_private_json(
    path: &Path,
    content: &[u8],
    description: &str,
) -> Result<(), String> {
    if content.len() as u64 > MAX_CATALOG_BYTES {
        return Err(format!("{description} exceeds the storage limit"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid {description} path: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {description} directory: {error}"))?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing to replace {description} through a non-file path"
            ));
        }
    }

    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".endpoints-{}-{sequence}.tmp", std::process::id()));
    let mut temp = crate::platform::create_private_state_file(&temp_path)
        .map_err(|error| format!("failed to create {description}: {error}"))?;
    if let Err(error) = temp.write_all(content).and_then(|()| temp.sync_all()) {
        drop(temp);
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to write {description}: {error}"));
    }
    drop(temp);
    if let Err(error) = crate::platform::replace_file(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to activate {description}: {error}"));
    }
    crate::platform::sync_parent_directory(parent)
        .map_err(|error| format!("failed to persist {description} directory: {error}"))
}

pub(crate) fn catalog_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("endpoints.json")
}

fn selection_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("endpoint-selection.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "herdr-endpoint-catalog-{}-{name}",
                std::process::id()
            ))
            .join("endpoints.json")
    }

    /// A dial-in catalog path next to `catalog_path` that tests never create.
    fn no_dial_in(catalog_path: &Path) -> PathBuf {
        catalog_path.with_file_name("absent-dial-in-machines.json")
    }

    /// The `endpoints.json` loader of Herdr releases without dial-in support,
    /// reproduced verbatim: strict fields and an SSH-only selection rule. Any
    /// failure here means an older binary would drop every saved SSH machine.
    fn load_strict_v1(path: &Path) -> Result<Vec<SavedSshEndpoint>, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct V1Catalog {
            version: u32,
            #[serde(default)]
            selected_profile: Option<ProfileId>,
            #[serde(default)]
            ssh: Vec<SavedSshEndpoint>,
        }
        let catalog: V1Catalog =
            serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if catalog.version != 1 {
            return Err("version".into());
        }
        let mut ids = HashSet::new();
        for profile in &catalog.ssh {
            profile.validate()?;
            if !ids.insert(profile.id.clone()) {
                return Err("duplicate id".into());
            }
        }
        if catalog.selected_profile.as_ref().is_some_and(|selected| {
            !catalog
                .ssh
                .iter()
                .any(|profile| &profile.id == selected && profile.enabled)
        }) {
            return Err("selected SSH endpoint is absent or disabled in the catalog".into());
        }
        Ok(catalog.ssh)
    }

    #[test]
    fn dial_in_selection_never_leaks_into_strict_v1_endpoints_json() {
        let catalog_path = path("dial-in-selection-leak");
        let dial_in_path = catalog_path.with_file_name("dial-in-machines.json");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());

        let mut catalog = EndpointCatalog::default();
        let keep = catalog.add_ssh("Keep", "keep", "default").unwrap();
        let toggled = catalog.add_ssh("Toggle", "toggle", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let mut dial_in = DialInCatalog::default();
        let laptop = dial_in
            .add("Laptop", "default", &[keep.clone(), toggled.clone()])
            .unwrap();
        dial_in.store_to_path(&dial_in_path).unwrap();

        let mut catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &dial_in_path, &selection_path)
                .unwrap();
        assert_eq!(catalog.dial_in.len(), 1);
        assert!(catalog.has_enabled_machines());
        assert!(catalog.select_endpoint(&super::super::ClientEndpointId::Ssh(laptop.clone())));
        catalog.store_selection_to_path(&selection_path).unwrap();
        let mut catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &dial_in_path, &selection_path)
                .unwrap();
        assert_eq!(catalog.selected_profile.as_ref(), Some(&laptop));

        let assert_v1 = |expected: &[(&ProfileId, &str, bool)]| {
            let profiles = load_strict_v1(&catalog_path).unwrap();
            let actual = profiles
                .iter()
                .map(|profile| (&profile.id, profile.label.as_str(), profile.enabled))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
            let current = EndpointCatalog::load_from_path(&catalog_path).unwrap();
            assert_eq!(current.selected_profile, None);
            assert!(!std::fs::read_to_string(&catalog_path)
                .unwrap()
                .contains(laptop.as_str()));
        };

        let added = catalog.add_ssh("Added", "added", "default").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        assert_v1(&[
            (&keep, "Keep", true),
            (&toggled, "Toggle", true),
            (&added, "Added", true),
        ]);
        assert!(catalog.rename_ssh(&keep, "Kept").unwrap());
        catalog.store_to_path(&catalog_path).unwrap();
        assert_v1(&[
            (&keep, "Kept", true),
            (&toggled, "Toggle", true),
            (&added, "Added", true),
        ]);
        assert!(catalog.set_enabled(&toggled, false));
        catalog.store_to_path(&catalog_path).unwrap();
        assert_v1(&[
            (&keep, "Kept", true),
            (&toggled, "Toggle", false),
            (&added, "Added", true),
        ]);
        assert!(catalog.set_enabled(&toggled, true));
        catalog.store_to_path(&catalog_path).unwrap();
        assert!(catalog.remove_ssh(&added));
        catalog.store_to_path(&catalog_path).unwrap();
        assert_v1(&[(&keep, "Kept", true), (&toggled, "Toggle", true)]);
        assert_eq!(catalog.selected_profile.as_ref(), Some(&laptop));

        // An SSH selection is still recorded exactly as before.
        assert!(catalog.select_ssh(&keep));
        catalog.store_to_path(&catalog_path).unwrap();
        assert!(load_strict_v1(&catalog_path).is_ok());
        assert_eq!(
            EndpointCatalog::load_from_path(&catalog_path)
                .unwrap()
                .selected_profile,
            Some(keep.clone())
        );
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn via_selection_never_leaks_into_strict_v1_endpoints_json_and_survives_restarts() {
        let catalog_path = path("via-selection-leak");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let keep = catalog.add_ssh("Keep", "keep", "default").unwrap();
        let relay = ProfileId::generate();
        let link = ProfileId::generate();
        let via = ViaMachine {
            id: super::super::via_id(&relay, &link),
            relay_id: relay,
            relay_label: "vps".into(),
            relay_target: "me@vps".into(),
            link_id: link,
            label: "slave1".into(),
            session: "default".into(),
            connected: true,
        };
        catalog.set_via(vec![via.clone()]);
        assert!(catalog.has_enabled_machines());
        assert_eq!(
            catalog.machine_summaries().last().unwrap(),
            &SavedMachineSummary {
                id: via.id.clone(),
                label: "vps/slave1".into(),
                enabled: true,
                kind: SavedMachineKind::Via,
            }
        );
        assert!(catalog.select_endpoint(&super::super::ClientEndpointId::Ssh(via.id.clone())));
        catalog.store_selection_to_path(&selection_path).unwrap();
        assert!(catalog.rename_ssh(&keep, "Kept").unwrap());
        catalog.store_to_path(&catalog_path).unwrap();
        assert_eq!(load_strict_v1(&catalog_path).unwrap().len(), 1);
        assert!(!std::fs::read_to_string(&catalog_path)
            .unwrap()
            .contains(via.id.as_str()));

        // Relays list their machines only after startup: the selection waits.
        let no_dial_in = no_dial_in(&catalog_path);
        let mut restarted =
            EndpointCatalog::load_from_paths(&catalog_path, &no_dial_in, &selection_path).unwrap();
        assert_eq!(restarted.selected_profile, None);
        restarted.set_via(Vec::new());
        assert_eq!(restarted.selected_profile, None);
        restarted.set_via(vec![via.clone()]);
        assert_eq!(restarted.selected_profile.as_ref(), Some(&via.id));
        // Choosing Local first drops the pending selection.
        let mut restarted =
            EndpointCatalog::load_from_paths(&catalog_path, &no_dial_in, &selection_path).unwrap();
        restarted.select_local();
        restarted.set_via(vec![via.clone()]);
        assert_eq!(restarted.selected_profile, None);

        // endpoints.json still names an older SSH selection (a catalog
        // command stored it): the via selection wins once relays list it.
        let mut catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &no_dial_in, &selection_path).unwrap();
        catalog.selected_profile = Some(keep.clone());
        catalog.store_to_path(&catalog_path).unwrap();
        let mut restarted =
            EndpointCatalog::load_from_paths(&catalog_path, &no_dial_in, &selection_path).unwrap();
        assert_eq!(restarted.selected_profile.as_ref(), Some(&keep));
        assert_eq!(restarted.pending_selection.as_ref(), Some(&via.id));
        restarted.set_relays_enabled(true);
        assert_eq!(restarted.selected_profile, None);
        restarted.set_via(vec![via.clone()]);
        assert_eq!(restarted.selected_profile.as_ref(), Some(&via.id));
        // Without enabled relays, the SSH selection stays.
        let mut restarted =
            EndpointCatalog::load_from_paths(&catalog_path, &no_dial_in, &selection_path).unwrap();
        restarted.set_relays_enabled(false);
        assert_eq!(restarted.selected_profile.as_ref(), Some(&keep));
        assert_eq!(restarted.pending_selection, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn dial_in_selection_is_validated_against_enabled_dial_in_machines() {
        let catalog_path = path("dial-in-selection-validity");
        let dial_in_path = catalog_path.with_file_name("dial-in-machines.json");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut dial_in = DialInCatalog::default();
        let laptop = dial_in.add("Laptop", "default", &[]).unwrap();
        dial_in.store_to_path(&dial_in_path).unwrap();
        let mut catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &dial_in_path, &selection_path)
                .unwrap();
        assert!(catalog.ssh.is_empty());
        assert!(!catalog.has_enabled_ssh());
        assert!(catalog.has_enabled_machines());
        assert_eq!(
            catalog.machine_summaries(),
            vec![SavedMachineSummary {
                id: laptop.clone(),
                label: "Laptop".into(),
                enabled: true,
                kind: SavedMachineKind::DialIn,
            }]
        );
        assert!(catalog.select_ssh(&laptop));
        catalog.store_selection_to_path(&selection_path).unwrap();

        dial_in.set_enabled(&laptop, false);
        dial_in.store_to_path(&dial_in_path).unwrap();
        let mut catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &dial_in_path, &selection_path)
                .unwrap();
        assert_eq!(catalog.selected_profile, None);
        assert!(!catalog.has_enabled_machines());
        assert!(!catalog.select_ssh(&laptop));

        // An unusable dial-in catalog never costs the SSH machines.
        let ssh = catalog.add_ssh("Build", "build", "default").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(&dial_in_path, b"{not json").unwrap();
        let catalog =
            EndpointCatalog::load_from_paths(&catalog_path, &dial_in_path, &selection_path)
                .unwrap();
        assert_eq!(catalog.ssh[0].id, ssh);
        assert!(catalog.dial_in.is_empty());
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn dial_in_machines_colliding_with_ssh_ids_are_ignored() {
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "default").unwrap();
        let colliding = DialInMachine {
            id: id.clone(),
            ..DialInMachine::new("Laptop", "default").unwrap()
        };
        let other = DialInMachine::new("Desktop", "default").unwrap();
        let kept = dial_in_without_id_collisions(&catalog.ssh, vec![colliding, other.clone()]);
        assert_eq!(kept, vec![other]);
    }

    #[test]
    fn catalog_roundtrip_persists_profiles_without_secret_fields() {
        let path = path("roundtrip");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog
            .add_ssh("Build", "ssh://dev@build.example:2222", "agents")
            .unwrap();
        assert!(catalog.select_ssh(&id));
        catalog.store_to_path(&path).unwrap();

        let encoded = std::fs::read_to_string(&path).unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("control_socket"));
        let loaded = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(loaded, catalog);
        assert_eq!(loaded.ssh[0].id, id);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn duplicate_target_and_session_profiles_keep_distinct_opaque_ids() {
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "build", "default").unwrap();
        let second = catalog.add_ssh("Two", "build", "default").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn catalog_rejects_passwords_embedded_in_ssh_targets() {
        let mut catalog = EndpointCatalog::default();
        assert!(catalog
            .add_ssh("Build", "ssh://dev:secret@build.example", "default")
            .unwrap_err()
            .contains("must not contain a password"));
        assert!(catalog
            .add_ssh("Build", "dev:secret@build.example", "default")
            .is_err());
        assert!(catalog
            .add_ssh("Build", "ssh://dev@[::1]:2222", "default")
            .is_ok());
    }

    #[test]
    fn interactive_bootstrap_matches_only_enabled_target_and_session() {
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        assert!(catalog.contains_enabled_target_session("build", "agents"));
        assert!(!catalog.contains_enabled_target_session("build", "default"));
        assert!(catalog.set_enabled(&id, false));
        assert!(!catalog.contains_enabled_target_session("build", "agents"));
    }

    #[test]
    fn rename_changes_only_the_machine_label() {
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Old", "build", "agents").unwrap();
        let original = catalog.ssh[0].clone();

        assert!(catalog.rename_ssh(&id, "New").unwrap());
        assert_eq!(catalog.ssh[0].label, "New");
        assert_eq!(catalog.ssh[0].id, original.id);
        assert_eq!(catalog.ssh[0].target, original.target);
        assert_eq!(catalog.ssh[0].session, original.session);
        assert!(catalog.rename_ssh(&id, "\n").is_err());
        assert_eq!(catalog.ssh[0].label, "New");
    }

    #[test]
    fn removal_and_disable_return_selection_to_local() {
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "one", "default").unwrap();
        assert!(catalog.select_ssh(&first));
        assert!(catalog.set_enabled(&first, false));
        assert_eq!(catalog.selected_profile, None);

        assert!(catalog.set_enabled(&first, true));
        assert!(catalog.select_ssh(&first));
        assert!(catalog.remove_ssh(&first));
        assert_eq!(catalog.selected_profile, None);
    }

    #[test]
    fn catalog_rejects_unknown_fields_instead_of_retaining_possible_secrets() {
        let path = path("unknown-field");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{
              "version": 1,
              "ssh": [{
                "id": "0123456789abcdef0123456789abcdef",
                "label": "Build",
                "target": "build",
                "session": "default",
                "enabled": true,
                "password": "must-not-be-accepted"
              }]
            }"#,
        )
        .unwrap();
        assert!(EndpointCatalog::load_from_path(&path)
            .unwrap_err()
            .contains("unknown field"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn storing_selection_does_not_rewrite_profile_membership() {
        let catalog_path = path("separate-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let profiles_before = std::fs::read(&catalog_path).unwrap();

        assert!(catalog.select_ssh(&id));
        catalog.store_selection_to_path(&selection_path).unwrap();

        assert_eq!(std::fs::read(&catalog_path).unwrap(), profiles_before);
        assert_eq!(
            load_selection_from_path(&selection_path)
                .unwrap()
                .unwrap()
                .selected_profile,
            Some(id)
        );
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn malformed_selection_does_not_discard_saved_profiles() {
        let catalog_path = path("malformed-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(&selection_path, b"not json").unwrap();

        let loaded = EndpointCatalog::load_from_paths(
            &catalog_path,
            &no_dial_in(&catalog_path),
            &selection_path,
        )
        .unwrap();
        assert_eq!(loaded.ssh.len(), 1);
        assert_eq!(loaded.ssh[0].id, id);
        assert_eq!(loaded.selected_profile, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn absent_selected_profile_falls_back_without_discarding_catalog() {
        let catalog_path = path("absent-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let saved = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let missing = ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap();
        store_private_json(
            &selection_path,
            &serde_json::to_vec(&EndpointSelection {
                version: SELECTION_VERSION,
                selected_profile: Some(missing),
            })
            .unwrap(),
            "endpoint selection",
        )
        .unwrap();

        let loaded = EndpointCatalog::load_from_paths(
            &catalog_path,
            &no_dial_in(&catalog_path),
            &selection_path,
        )
        .unwrap();
        assert_eq!(loaded.ssh[0].id, saved);
        assert_eq!(loaded.selected_profile, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_or_missing_selected_profile_is_rejected() {
        let catalog = EndpointCatalog {
            selected_profile: Some(ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()),
            ..EndpointCatalog::default()
        };
        assert!(catalog.validate().is_err());
    }
}
