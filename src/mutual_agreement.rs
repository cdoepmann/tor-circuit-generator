use std::cmp::Ordering;

use seeded_rand::RHashMap;

#[derive(PartialEq, Clone, Copy)]
pub enum Possibility<T> {
    // No,
    Maybe(T),
    Yes,
}

pub struct MutualAgreement {
    map: RHashMap<(String, String), Possibility<String>>,
}

impl MutualAgreement {
    pub fn new() -> Self {
        MutualAgreement {
            map: RHashMap::default(),
        }
    }
    pub fn agree(&mut self, a: &str, b: &str) {
        let key = calculate_key(a, b);
        match self.map.get(&key) {
            Some(value) => {
                if *value == Possibility::Maybe(String::from(b)) {
                    let _trash = self.map.insert(key, Possibility::Yes);
                }
            }
            None => {
                let _trash = self.map.insert(key, Possibility::Maybe(String::from(a)));
            }
        }
    }
    pub fn agreement_exists(&self, a: &str, b: &str) -> bool {
        let key = calculate_key(a, b);
        match self.map.get(&key) {
            Some(Possibility::Yes) => true,
            _ => false,
        }
    }

    pub fn into_agreement_map(self) -> RHashMap<String, RHashMap<String, bool>> {
        let mut agreement_map: RHashMap<String, RHashMap<String, bool>> = RHashMap::default();
        for (k, v) in self.map {
            if v == Possibility::Yes {
                let (a, b) = k;
                let sub_map_a = safe_get_mut(&mut agreement_map, &a);
                // TODO ugly
                sub_map_a.insert(b.clone(), true);
                let sub_map_b = safe_get_mut(&mut agreement_map, &b);
                sub_map_b.insert(a, true);
            }
        }
        agreement_map
    }
}
fn safe_get_mut<'a>(
    map: &'a mut RHashMap<String, RHashMap<String, bool>>,
    key: &str,
) -> &'a mut RHashMap<String, bool> {
    if !map.contains_key(key) {
        map.insert(String::from(key), RHashMap::default());
    }
    match map.get_mut(key) {
        Some(map) => map,
        _ => panic!("Safe_get was not safe. Key: {}", key),
    }
}

pub fn calculate_key(a: &str, b: &str) -> (String, String) {
    if a.cmp(&b) == Ordering::Less {
        (String::from(a), String::from(b))
    } else {
        (String::from(b), String::from(a))
    }
}

#[test]
fn agree_test() {
    let mut agreement = MutualAgreement::new();
    assert_eq!(agreement.agreement_exists("1", "2"), false);
    assert_eq!(agreement.agreement_exists("2", "1"), false);
    agreement.agree("1", "2");
    assert_eq!(agreement.agreement_exists("1", "2"), false);
    assert_eq!(agreement.agreement_exists("2", "1"), false);
    agreement.agree("2", "1");
    assert_eq!(agreement.agreement_exists("1", "2"), true);
    assert_eq!(agreement.agreement_exists("2", "1"), true);
}

#[test]
fn calc_key() {
    let key = calculate_key("1", "2");
    assert_eq!(key, (String::from("1"), String::from("2")));
}

#[test]
fn calc_key_ordering() {
    let key = calculate_key("foo", "bar");
    assert_eq!(key, (String::from("bar"), String::from("foo")));
}

#[test]
fn into_agreement_map_test() {
    let mut agreement = MutualAgreement::new();
    agreement.agree("1", "2");
    agreement.agree("2", "1");
    agreement.agree("1", "3");
    agreement.agree("3", "1");
    agreement.agree("3", "2");
    assert_eq!(agreement.agreement_exists("1", "2"), true);
    assert_eq!(agreement.agreement_exists("2", "1"), true);
    assert_eq!(agreement.agreement_exists("1", "3"), true);
    assert_eq!(agreement.agreement_exists("3", "1"), true);
    assert_eq!(agreement.agreement_exists("3", "2"), false);
    assert_eq!(agreement.agreement_exists("2", "3"), false);

    let a_map = agreement.into_agreement_map();
    if let Some(submap) = a_map.get("1") {
        assert_eq!(submap.get("2"), Some(&true));
    } else {
        panic!("Map did not contain a submap for value 1")
    }

    if let Some(submap) = a_map.get("1") {
        assert_eq!(submap.get("3"), Some(&true));
    } else {
        panic!("Map did not contain a submap for value 1")
    }

    if let Some(submap) = a_map.get("2") {
        assert_eq!(submap.get("1"), Some(&true));
    } else {
        panic!("Map did not contain a submap for value 1")
    }

    if let Some(submap) = a_map.get("2") {
        assert_eq!(submap.get("3"), None);
    } else {
        panic!("Map did not contain a submap for value 1")
    }

    if let Some(submap) = a_map.get("3") {
        assert_eq!(submap.get("1"), Some(&true));
    } else {
        panic!("Map did not contain a submap for value 1")
    }

    if let Some(submap) = a_map.get("3") {
        assert_eq!(submap.get("2"), None);
    } else {
        panic!("Map did not contain a submap for value 1")
    }
}
