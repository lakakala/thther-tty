//! The daemon's table of live sessions.

use super::session::SessionShared;
use crate::proto::control::SessionInfo;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Registry {
    map: Mutex<HashMap<String, Arc<SessionShared>>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { map: Mutex::new(HashMap::new()) }
    }
    pub fn insert(&self, s: Arc<SessionShared>) {
        self.map.lock().unwrap().insert(s.id.clone(), s);
    }
    pub fn get(&self, id: &str) -> Option<Arc<SessionShared>> {
        self.map.lock().unwrap().get(id).cloned()
    }
    pub fn remove(&self, id: &str) {
        self.map.lock().unwrap().remove(id);
    }
    pub fn contains(&self, id: &str) -> bool {
        self.map.lock().unwrap().contains_key(id)
    }
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut v: Vec<SessionInfo> = self
            .map
            .lock()
            .unwrap()
            .values()
            .map(|s| SessionInfo {
                id: s.id.clone(),
                started: s.started,
                status: s.status_str(),
                cmd: s.cmd.clone(),
            })
            .collect();
        v.sort_by(|a, b| a.started.cmp(&b.started));
        v
    }
}
