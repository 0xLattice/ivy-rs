//! Configuration decoding keeps host ABI values separate from runtime limits.
use crate::codec::{decode, Kind, Value};
use ivy_core::{
    core::{CoreMode, CoreSettings},
    Config, PeerEndpoint, PeerKey,
};
use std::time::Duration;
pub struct Configuration {
    pub identity: Config,
    pub settings: CoreSettings,
    pub listen_port: u16,
}
pub(crate) fn fields(value: &Value) -> Option<&[Value]> {
    if let Value::Fields(v) = value {
        Some(v)
    } else {
        None
    }
}
pub(crate) fn list(value: &Value) -> Option<&[Value]> {
    if let Value::List(v) = value {
        Some(v)
    } else {
        None
    }
}
pub(crate) fn string(value: &Value) -> Option<&str> {
    if let Value::String(v) = value {
        Some(v)
    } else {
        None
    }
}
pub(crate) fn unsigned(value: &Value) -> Option<u64> {
    if let Value::Unsigned(v) = value {
        Some(*v)
    } else {
        None
    }
}
pub(crate) fn boolean(value: &Value) -> Option<bool> {
    if let Value::Bool(v) = value {
        Some(*v)
    } else {
        None
    }
}
pub(crate) fn bytes(value: &Value) -> Option<&[u8]> {
    if let Value::Bytes(v) = value {
        Some(v)
    } else {
        None
    }
}
pub(crate) fn optional(value: &Value) -> Option<Option<&Value>> {
    if let Value::Optional(v) = value {
        Some(v.as_deref())
    } else {
        None
    }
}
pub(crate) fn tagged(value: &Value) -> Option<(u8, &[Value])> {
    if let Value::Tagged { tag, fields } = value {
        Some((*tag, fields))
    } else {
        None
    }
}
pub(crate) fn size(value: &Value) -> Option<usize> {
    if let Value::Signed(v) = value {
        Some(usize::try_from((*v).max(1)).unwrap_or(usize::MAX))
    } else {
        None
    }
}
pub(crate) fn duration(value: &Value) -> Option<Duration> {
    let f = fields(value)?;
    let (Value::Signed(s), Value::Signed(a)) = (&f[0], &f[1]) else {
        return None;
    };
    if *s < 0 || *a < 0 {
        return None;
    }
    Some(Duration::new(*s as u64, (*a / 1_000_000_000) as u32))
}
pub(crate) fn endpoint(value: &Value) -> Option<PeerEndpoint> {
    let f = fields(value)?;
    Some(PeerEndpoint {
        public_key: string(&f[0])?.into(),
        host: string(&f[1])?.into(),
        port: unsigned(&f[2])? as u16,
    })
}
impl Configuration {
    pub fn decode(encoded: &[u8]) -> Option<Self> {
        let value = decode(Kind::Config, encoded)?;
        let f = fields(&value)?;
        let seed: [u8; 32] = bytes(&f[0])?.try_into().ok()?;
        let mut identity = Config::new(ed25519_dalek::SigningKey::from_bytes(&seed));
        let mut settings = CoreSettings::default();
        let mut listen_port = 4001;
        if let Some(v) = optional(&f[1])? {
            listen_port = unsigned(v)? as u16;
        }
        if let Some(v) = optional(&f[2])? {
            settings.bootstrap_peers = list(v)?.iter().map(endpoint).collect::<Option<_>>()?;
        }
        if let Some(v) = optional(&f[3])? {
            settings.carriers = list(v)?.iter().map(endpoint).collect::<Option<_>>()?;
        }
        if let Some(v) = optional(&f[4])? {
            settings.relay_enabled = boolean(v)?;
        }
        if let Some(v) = optional(&f[5])? {
            let (tag, f) = tagged(v)?;
            settings.mode = match tag {
                0 => CoreMode::Overlay,
                1 => CoreMode::PrivateNetwork,
                2 => CoreMode::Pinned(PeerKey::from_hex(string(&f[0])?)?),
                _ => return None,
            };
        }
        if let Some(v) = optional(&f[6])? {
            settings.private_content_exchange_enabled = boolean(v)?;
        }
        if let Some(v) = optional(&f[7])? {
            settings.request_timeout = duration(v)?;
        }
        if let Some(v) = optional(&f[8])? {
            settings.keepalive_interval = duration(v)?;
        }
        if let Some(v) = optional(&f[9])? {
            settings.stale_timeout = duration(v)?;
        }
        if let Some(v) = optional(&f[10])? {
            settings.max_missed_pongs = size(v)?.min(u32::MAX as usize) as u32;
        }
        if let Some(v) = optional(&f[11])? {
            settings.health_enabled = boolean(v)?;
        }
        if let Some(v) = optional(&f[12])? {
            identity.metadata.max_frame_size = unsigned(v)? as u32;
        }
        if let Some(v) = optional(&f[13])? {
            settings.max_connections = size(v)?;
            settings.max_inbound_connections = settings.max_connections;
        }
        if let Some(v) = optional(&f[14])? {
            settings.max_connections_per_netgroup = size(v)?;
        }
        if let Some(v) = optional(&f[15])? {
            settings.max_pending_requests = size(v)?;
        }
        if let Some(v) = optional(&f[16])? {
            settings.max_concurrent_content_requests = size(v)?;
        }
        if let Some(v) = optional(&f[17])? {
            settings.max_inbound_bytes = size(v)?;
        }
        if let Some(v) = optional(&f[18])? {
            settings.max_in_flight_volume_bytes = size(v)?;
        }
        settings.listen_port = Some(listen_port);
        Some(Self {
            identity,
            settings,
            listen_port,
        })
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        self.settings.validate(&self.identity)
    }
}
