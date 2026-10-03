//! Relay hubs (`relays.json`) and the dial-in machines reached through them.
//!
//! A relay hub is a machine this client reaches over SSH that has its own
//! dial-in machines (see `crate::remote::link`). This client reaches those
//! machines through the hub with `herdr link-connect`, as "via" machines that
//! exist only in memory, derived from the hub's listing. The file is separate
//! from `endpoints.json`, which stays strict v1, and preserves unknown fields.

use std::collections::HashSet;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::catalog::store_private_json;
use super::{EndpointCatalog, ProfileId, MAX_LABEL_BYTES, PROFILE_ID_BYTES};

const RELAY_CATALOG_VERSION: u32 = 1;
const MAX_RELAY_CATALOG_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_RELAYS: usize = 64;
const MAX_TARGET_BYTES: usize = 1024;
const MAX_ID_ATTEMPTS: usize = 16;
/// Version of the JSON that `herdr link-connect --list` prints.
pub(crate) const RELAY_LISTING_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelayHub {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) target: String,
    pub(crate) enabled: bool,
    /// Fields written by newer Herdr versions; preserved on rewrite.
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl RelayHub {
    fn validate(&self) -> Result<(), String> {
        ProfileId::parse(self.id.to_string())?;
        validate_relay_label(&self.label)?;
        validate_relay_target(&self.target)
    }
}

/// Relay labels prefix their machines' labels (`<relay>/<machine>`), so they
/// cannot contain `/`.
fn validate_relay_label(label: &str) -> Result<(), String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("relay hub label cannot be empty".into());
    }
    if label.len() > MAX_LABEL_BYTES || label.chars().any(|ch| ch.is_control() || ch == '/') {
        return Err(format!(
            "relay hub label must be at most {MAX_LABEL_BYTES} bytes and contain no '/' or control characters"
        ));
    }
    Ok(())
}

/// The rules of saved SSH machine targets.
pub(crate) fn validate_relay_target(target: &str) -> Result<(), String> {
    if target.len() > MAX_TARGET_BYTES || target.chars().any(char::is_control) {
        return Err(format!(
            "SSH target must be at most {MAX_TARGET_BYTES} bytes and contain no control characters"
        ));
    }
    crate::remote::validate_remote_target(target)
        .map_err(|_| "SSH target must not be empty or start with '-'".to_string())?;
    let authority = target.strip_prefix("ssh://").unwrap_or(target);
    if authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
    {
        return Err("SSH target must not contain a password".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelayCatalog {
    version: u32,
    #[serde(default)]
    pub(crate) relays: Vec<RelayHub>,
    /// Fields written by newer Herdr versions; preserved on rewrite.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Default for RelayCatalog {
    fn default() -> Self {
        Self {
            version: RELAY_CATALOG_VERSION,
            relays: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

impl RelayCatalog {
    /// Loads the default catalog; a missing file is an empty catalog.
    pub(crate) fn load() -> Result<Self, String> {
        Self::load_from_path(&relay_catalog_path())
    }

    pub(crate) fn load_from_path(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(format!(
                    "failed to open relay hub catalog {}: {error}",
                    path.display()
                ))
            }
        };
        let mut content = String::new();
        file.take(MAX_RELAY_CATALOG_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("failed to read relay hub catalog: {error}"))?;
        if content.len() as u64 > MAX_RELAY_CATALOG_BYTES {
            return Err("relay hub catalog exceeds the storage limit".into());
        }
        let catalog: Self = serde_json::from_str(&content)
            .map_err(|error| format!("stored relay hub catalog is invalid: {error}"))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub(crate) fn store(&self) -> Result<(), String> {
        self.store_to_path(&relay_catalog_path())
    }

    pub(crate) fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to encode relay hub catalog: {error}"))?;
        store_private_json(path, &content, "relay hub catalog")
    }

    /// Adds an enabled relay hub whose id collides with neither this catalog
    /// nor `taken_ids`. The label is trimmed and must be unique.
    pub(crate) fn add(
        &mut self,
        label: &str,
        target: &str,
        taken_ids: &[ProfileId],
    ) -> Result<ProfileId, String> {
        if self.relays.len() >= MAX_RELAYS {
            return Err(format!("at most {MAX_RELAYS} relay hubs can be saved"));
        }
        let mut relay = RelayHub {
            id: ProfileId::generate(),
            label: label.trim().to_string(),
            target: target.to_string(),
            enabled: true,
            extra: serde_json::Map::new(),
        };
        relay.validate()?;
        self.check_label_free(&relay.label, None)?;
        let mut attempts = 0;
        while taken_ids.contains(&relay.id) || self.relays.iter().any(|item| item.id == relay.id) {
            attempts += 1;
            if attempts >= MAX_ID_ATTEMPTS {
                return Err("failed to generate a unique relay hub id".into());
            }
            relay.id = ProfileId::generate();
        }
        let id = relay.id.clone();
        self.relays.push(relay);
        Ok(id)
    }

    /// A relay hub by id, then by (trimmed) label.
    pub(crate) fn find(&self, selector: &str) -> Result<&RelayHub, String> {
        let selector = selector.trim();
        self.relays
            .iter()
            .find(|relay| relay.id.as_str() == selector)
            .or_else(|| {
                self.relays
                    .iter()
                    .find(|relay| relay.label.trim() == selector)
            })
            .ok_or_else(|| {
                format!("unknown relay hub '{selector}'; use `herdr machine relay list`")
            })
    }

    pub(crate) fn rename(&mut self, id: &ProfileId, label: &str) -> Result<(), String> {
        let label = label.trim();
        validate_relay_label(label)?;
        self.check_label_free(label, Some(id))?;
        let relay = self
            .relays
            .iter_mut()
            .find(|relay| &relay.id == id)
            .ok_or_else(|| format!("relay hub {id} was not found"))?;
        relay.label = label.to_string();
        Ok(())
    }

    pub(crate) fn set_enabled(&mut self, id: &ProfileId, enabled: bool) -> bool {
        let Some(relay) = self.relays.iter_mut().find(|relay| &relay.id == id) else {
            return false;
        };
        relay.enabled = enabled;
        true
    }

    pub(crate) fn remove(&mut self, id: &ProfileId) -> bool {
        let previous_len = self.relays.len();
        self.relays.retain(|relay| &relay.id != id);
        self.relays.len() != previous_len
    }

    pub(crate) fn enabled(&self) -> impl Iterator<Item = &RelayHub> {
        self.relays.iter().filter(|relay| relay.enabled)
    }

    fn check_label_free(&self, label: &str, except: Option<&ProfileId>) -> Result<(), String> {
        if self
            .relays
            .iter()
            .any(|relay| Some(&relay.id) != except && relay.label.trim() == label.trim())
        {
            return Err(format!(
                "a relay hub labeled '{}' already exists",
                label.trim()
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != RELAY_CATALOG_VERSION {
            return Err(format!(
                "unsupported relay hub catalog version {}; expected {RELAY_CATALOG_VERSION}",
                self.version
            ));
        }
        if self.relays.len() > MAX_RELAYS {
            return Err(format!(
                "relay hub catalog contains more than {MAX_RELAYS} relay hubs"
            ));
        }
        let mut ids = HashSet::new();
        let mut labels = HashSet::new();
        for relay in &self.relays {
            relay.validate()?;
            if !ids.insert(relay.id.clone()) {
                return Err(format!("duplicate relay hub id {}", relay.id));
            }
            if !labels.insert(relay.label.trim().to_string()) {
                return Err(format!(
                    "duplicate relay hub label '{}'",
                    relay.label.trim()
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn relay_catalog_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("relays.json")
}

/// A dial-in machine of a relay hub, reached through that hub. Derived from
/// the hub's listing and never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViaMachine {
    /// [`via_id`] of the relay and link: stable across restarts.
    pub(crate) id: ProfileId,
    pub(crate) relay_id: ProfileId,
    pub(crate) relay_label: String,
    pub(crate) relay_target: String,
    /// The machine's id in the hub's dial-in catalog.
    pub(crate) link_id: ProfileId,
    /// The machine's label on the hub.
    pub(crate) label: String,
    pub(crate) session: String,
    /// Whether the hub reported a live link; false while the hub is unreachable.
    pub(crate) connected: bool,
}

impl ViaMachine {
    /// `<relay label>/<machine label>`.
    pub(crate) fn display_label(&self) -> String {
        format!("{}/{}", self.relay_label.trim(), self.label.trim())
    }
}

/// The client-side id of link `link_id` reached through relay `relay_id`:
/// the first 16 bytes of `sha256("herdr-via:<relay>:<link>")`.
pub(crate) fn via_id(relay_id: &ProfileId, link_id: &ProfileId) -> ProfileId {
    let digest = Sha256::digest(format!("herdr-via:{relay_id}:{link_id}").as_bytes());
    ProfileId(
        digest[..PROFILE_ID_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// What `herdr link-connect --list` prints. Readers ignore unknown fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelayListing {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) machines: Vec<RelayListedMachine>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelayListedMachine {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) session: String,
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) connected: bool,
    #[serde(default)]
    pub(crate) link_epoch: u64,
}

/// A listed via machine and what the hub reported for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ListedVia {
    pub(crate) machine: ViaMachine,
    /// The hub refuses connections to a disabled machine; only management
    /// commands (to enable it again) reach it.
    pub(crate) enabled: bool,
    pub(crate) link_epoch: u64,
}

impl RelayListing {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let listing: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("the relay hub sent an invalid machine list: {error}"))?;
        if listing.version != RELAY_LISTING_VERSION {
            return Err(format!(
                "the relay hub sent machine list version {}; this Herdr understands {RELAY_LISTING_VERSION}",
                listing.version
            ));
        }
        Ok(listing)
    }

    /// The valid machines of `relay`'s listing, enabled or not (at most as
    /// many as a dial-in catalog holds), skipping invalid entries.
    pub(crate) fn via_machines(&self, relay: &RelayHub) -> Vec<ListedVia> {
        self.machines
            .iter()
            .filter_map(|listed| {
                let link_id = ProfileId::parse(listed.id.clone()).ok()?;
                let label = listed.label.trim();
                let valid = !label.is_empty()
                    && label.len() <= MAX_LABEL_BYTES
                    && !label.chars().any(char::is_control)
                    && crate::session::validate_name(&listed.session).is_ok();
                if !valid {
                    tracing::debug!(relay = %relay.id, link = %link_id, "skipping an invalid relay listing entry");
                    return None;
                }
                Some(ListedVia {
                    machine: ViaMachine {
                        id: via_id(&relay.id, &link_id),
                        relay_id: relay.id.clone(),
                        relay_label: relay.label.trim().to_string(),
                        relay_target: relay.target.clone(),
                        link_id,
                        label: label.to_string(),
                        session: listed.session.clone(),
                        connected: listed.connected,
                    },
                    enabled: listed.enabled,
                    link_epoch: listed.link_epoch,
                })
            })
            .take(super::dial_in_catalog::MAX_DIAL_IN_MACHINES)
            .collect()
    }
}

impl EndpointCatalog {
    /// Replaces the via machines and adopts a selection loaded before they
    /// were known, once a relay lists it.
    pub(crate) fn set_via(&mut self, via: Vec<ViaMachine>) {
        self.via = via;
        if self.selected_profile.is_none() {
            if let Some(pending) = self.pending_selection.take() {
                if self.via.iter().any(|machine| machine.id == pending) {
                    self.selected_profile = Some(pending);
                } else {
                    self.pending_selection = Some(pending);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("herdr-relay-catalog-{}-{name}", std::process::id()))
            .join("relays.json")
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn relay(label: &str) -> RelayHub {
        RelayHub {
            id: ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            label: label.into(),
            target: "me@vps".into(),
            enabled: true,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn relay_catalog_round_trips_and_missing_file_is_empty() {
        let path = path("roundtrip");
        cleanup(&path);
        assert_eq!(
            RelayCatalog::load_from_path(&path).unwrap(),
            RelayCatalog::default()
        );
        let mut catalog = RelayCatalog::default();
        let taken = ProfileId::generate();
        let vps = catalog
            .add(" vps ", "me@vps.example", std::slice::from_ref(&taken))
            .unwrap();
        let lab = catalog.add("lab", "ssh://me@lab:2222", &[]).unwrap();
        assert_ne!(vps, taken);
        assert!(catalog.set_enabled(&lab, false));
        catalog.store_to_path(&path).unwrap();
        let loaded = RelayCatalog::load_from_path(&path).unwrap();
        assert_eq!(loaded, catalog);
        assert_eq!(loaded.find("vps").unwrap().id, vps);
        assert_eq!(loaded.find(lab.as_str()).unwrap().label, "lab");
        assert!(loaded.find("missing").is_err());
        assert_eq!(
            loaded.enabled().map(|relay| &relay.id).collect::<Vec<_>>(),
            vec![&vps]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }

        let mut catalog = loaded;
        assert!(catalog.rename(&vps, "lab").is_err());
        catalog.rename(&vps, "hub").unwrap();
        assert_eq!(catalog.find("hub").unwrap().id, vps);
        assert!(catalog.remove(&lab));
        assert!(!catalog.remove(&lab));
        assert!(!catalog.set_enabled(&lab, true));
        cleanup(&path);
    }

    #[test]
    fn relay_catalog_preserves_unknown_fields() {
        let path = path("unknown");
        cleanup(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"version":1,"future":{"a":1},"relays":[{"id":"0123456789abcdef0123456789abcdef","label":"vps","target":"me@vps","enabled":true,"jump":"bastion"}]}"#,
        )
        .unwrap();
        let mut catalog = RelayCatalog::load_from_path(&path).unwrap();
        let id = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        catalog.rename(&id, "hub").unwrap();
        catalog.store_to_path(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["future"], serde_json::json!({"a": 1}));
        assert_eq!(value["relays"][0]["jump"], "bastion");
        assert_eq!(value["relays"][0]["label"], "hub");
        cleanup(&path);
    }

    #[test]
    fn relay_catalog_validation_rejects_bad_content() {
        let id = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        let entry = |id: &str, label: &str, target: &str| serde_json::json!({"id": id, "label": label, "target": target, "enabled": true});
        let many = (0..=MAX_RELAYS)
            .map(|index| entry(&format!("{index:032x}"), &format!("r{index}"), "vps"))
            .collect::<Vec<_>>();
        let cases = [
            serde_json::json!({"version": 2, "relays": []}),
            serde_json::json!({"relays": []}),
            serde_json::json!({"version": 1, "relays": [entry("XYZ", "a", "vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, " ", "vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a/b", "vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a\u{1b}", "vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "-oProxyCommand=x")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "me:secret@vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "vps\nx")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "vps"), entry(id, "b", "vps")]}),
            serde_json::json!({"version": 1, "relays": [entry(id, "a", "vps"), entry(other, " a", "vps")]}),
            serde_json::json!({"version": 1, "relays": [{"id": id, "label": "a", "target": "vps"}]}),
            serde_json::json!({"version": 1, "relays": many}),
        ];
        for (index, case) in cases.iter().enumerate() {
            let path = path(&format!("invalid-{index}"));
            cleanup(&path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, serde_json::to_vec(case).unwrap()).unwrap();
            assert!(
                RelayCatalog::load_from_path(&path).is_err(),
                "case {index} should be rejected"
            );
            cleanup(&path);
        }
        let mut catalog = RelayCatalog::default();
        assert!(catalog.add("a/b", "vps", &[]).is_err());
        assert!(catalog.add("vps", "me:pw@vps", &[]).is_err());
        catalog.add("vps", "vps", &[]).unwrap();
        assert!(catalog.add(" vps", "other", &[]).is_err());
    }

    #[test]
    fn via_ids_are_stable_and_distinct_per_relay_and_link() {
        let relay = ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let link = ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap();
        assert_eq!(
            via_id(&relay, &link).as_str(),
            "453bd5bdb09752d6fd93e65be5b5b754"
        );
        assert_eq!(via_id(&relay, &link), via_id(&relay, &link));
        assert_ne!(via_id(&link, &relay), via_id(&relay, &link));
        assert_ne!(via_id(&relay, &link), link);
    }

    #[test]
    fn listing_parsing_ignores_unknown_fields_and_skips_unusable_entries() {
        let relay = relay("vps");
        let link = "fedcba9876543210fedcba9876543210";
        let listing = RelayListing::parse(
            serde_json::json!({
                "version": 1,
                "future": true,
                "machines": [
                    {"id": link, "label": " slave1 ", "session": "default", "enabled": true,
                     "connected": true, "link_epoch": 4, "os": "linux"},
                    {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "label": "off", "session": "default", "enabled": false},
                    {"id": "bad", "label": "bad id", "session": "default", "enabled": true},
                    {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "label": "bad session", "session": "a b", "enabled": true},
                    {"id": "cccccccccccccccccccccccccccccccc", "label": "\u{1b}[2J", "session": "default", "enabled": true},
                    {"id": "dddddddddddddddddddddddddddddddd", "label": "old", "session": "work", "enabled": true}
                ]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let machines = listing.via_machines(&relay);
        assert_eq!(machines.len(), 3);
        let first = &machines[0];
        assert!(first.enabled);
        assert_eq!(first.link_epoch, 4);
        assert_eq!(first.machine.label, "slave1");
        assert_eq!(first.machine.display_label(), "vps/slave1");
        assert!(first.machine.connected);
        assert_eq!(
            first.machine.id,
            via_id(&relay.id, &ProfileId::parse(link).unwrap())
        );
        assert_eq!(first.machine.relay_target, "me@vps");
        // Disabled machines are listed, for commands that enable them again.
        assert_eq!(machines[1].machine.label, "off");
        assert!(!machines[1].enabled);
        assert_eq!(machines[2].machine.session, "work");
        assert!(machines[2].enabled);
        assert!(!machines[2].machine.connected);
        assert_eq!(machines[2].link_epoch, 0);

        for invalid in [
            r#"{"version":2,"machines":[]}"#,
            r#"{"machines":[]}"#,
            "not json",
        ] {
            assert!(
                RelayListing::parse(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
        assert!(RelayListing::parse(br#"{"version":1}"#)
            .unwrap()
            .machines
            .is_empty());
    }
}
