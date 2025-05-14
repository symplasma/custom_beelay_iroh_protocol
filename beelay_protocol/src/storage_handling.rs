use std::collections::BTreeMap;
use ed25519_dalek::SigningKey;
use beelay_core::io::{IoAction, IoResult};
use signature::SignerMut;

pub type BeelayStorage = BTreeMap<beelay_core::StorageKey, Vec<u8>>;

/// function handles beelay tasks related to storage, currently implemented only for Btree, but will be implemented for proper CRDT storage in the future
pub fn handle_task(
    storage: &mut BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    signing_key: &mut SigningKey,
    task: beelay_core::io::IoTask,
) -> IoResult {
    let id = task.id();
    match task.take_action() {
        IoAction::Load { key } => {
            let data = storage.get(&key).cloned();
            IoResult::load(id, data)
        }
        IoAction::Put { key, data } => {
            storage.insert(key, data);
            IoResult::put(id)
        }
        IoAction::Delete { key } => {
            storage.remove(&key);
            IoResult::delete(id)
        }
        IoAction::LoadRange { prefix } => {
            let results = storage
                .iter()
                .filter_map(|(k, v)| {
                    if prefix.is_prefix_of(k) {
                        Some((k.clone(), v.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            IoResult::load_range(id, results)
        }
        IoAction::ListOneLevel { prefix } => {
            let keys_in_storage = storage.keys().map(|k| k.to_string()).collect::<Vec<_>>();
            tracing::trace!(prefix = ?prefix, ?keys_in_storage, "listing one level of storage");
            let results = storage
                .keys()
                .filter_map(|k| k.onelevel_deeper(&prefix))
                .collect();
            IoResult::list_one_level(id, results)
        }
        IoAction::Sign { payload } => {
            let signature = signing_key.sign(&payload);
            IoResult::sign(id, signature)
        }
    }
}