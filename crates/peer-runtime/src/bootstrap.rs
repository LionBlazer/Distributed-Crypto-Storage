//! Incompatible nested process bootstrap. No old flat JSON fallback.
use peer_transport::Identity;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::net::SocketAddr;

pub struct Bootstrap {
    pub identity: Identity,
    pub authority: Vec<u8>,
    pub owner: [u8; 32],
    pub node_id: u64,
    pub quota_bytes: u64,
    pub listen: SocketAddr,
}
#[derive(Serialize, Deserialize)]
#[serde(remote = "Bootstrap", deny_unknown_fields)]
struct Config {
    identity: Identity,
    authority: Vec<u8>,
    owner: [u8; 32],
    node_id: u64,
    quota_bytes: u64,
    listen: SocketAddr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u16,
    #[serde(with = "Config")]
    config: Bootstrap,
}
impl Serialize for Bootstrap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Out<'a> {
            version: u16,
            #[serde(with = "Config")]
            config: &'a Bootstrap,
        }
        Out {
            version: 2,
            config: self,
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Bootstrap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = Envelope::deserialize(deserializer)?;
        if envelope.version != 2 {
            return Err(de::Error::custom("Unsupported bootstrap version"));
        }
        Ok(envelope.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_v2_and_legacy_flat_bootstraps_reject_each_other_and_unknown_fields() {
        let identity = Identity {
            certificate: vec![],
            private_key_pkcs8: vec![],
        };
        let config = Bootstrap {
            identity,
            authority: vec![],
            owner: [1; 32],
            node_id: 1,
            quota_bytes: 4096,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let value = serde_json::to_value(config).unwrap();
        assert_eq!(value["version"], 2);
        assert!(value.get("identity").is_none());
        assert!(serde_json::from_value::<Bootstrap>(value.clone()).is_ok());
        let flat = value["config"].clone();
        assert!(serde_json::from_value::<Bootstrap>(flat).is_err());
        let mut wrong = value.clone();
        wrong["version"] = 1.into();
        assert!(serde_json::from_value::<Bootstrap>(wrong).is_err());
        let mut wrong = value.clone();
        wrong["unknown"] = true.into();
        assert!(serde_json::from_value::<Bootstrap>(wrong).is_err());
        let mut wrong = value.clone();
        wrong["config"]["unknown"] = true.into();
        assert!(serde_json::from_value::<Bootstrap>(wrong).is_err());
        #[derive(Deserialize)]
        struct OldRequired {
            #[serde(rename = "identity")]
            _identity: Identity,
        }
        assert!(serde_json::from_value::<OldRequired>(value).is_err());
    }
}
