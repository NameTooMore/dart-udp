use std::{fs, net::SocketAddr, path::Path, str::FromStr, time::Duration};

use serde::Deserialize;
use transfer_server::{RelayConfig, ServerConfig};

use crate::{cli::Cli, error::ConfigError};

const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 41000);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub server: ServerConfigFile,
    pub relay: RelayConfigFile,
}

impl AppConfig {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let config = Self::load_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_unvalidated(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(path) => toml::from_str(&fs::read_to_string(path)?)?,
            None => Self::default(),
        };
        config.apply_environment()?;
        Ok(config)
    }

    pub fn apply_cli(&mut self, cli: &Cli) -> Result<(), ConfigError> {
        if let Some(bind) = cli.bind {
            self.server.bind = bind;
        }
        if let Some(value) = cli.pairing_ttl_seconds {
            self.server.pairing_ttl_seconds = value;
        }
        if let Some(value) = cli.max_pairings {
            self.server.max_pairings = value;
        }
        if let Some(value) = cli.max_join_attempts {
            self.server.max_join_attempts = value;
        }
        if let Some(value) = cli.max_pending_messages {
            self.server.max_pending_messages = value;
        }
        if let Some(value) = cli.relay_max_bytes_per_session {
            self.relay.max_bytes_per_session = value;
        }
        if let Some(value) = cli.relay_max_bytes_total {
            self.relay.max_bytes_total = value;
        }
        if let Some(value) = cli.relay_max_streams_per_session {
            self.relay.max_streams_per_session = value;
        }
        if let Some(value) = cli.relay_buffer_size {
            self.relay.buffer_size = value;
        }
        self.validate()
    }

    pub fn server_config(&self) -> Result<ServerConfig, ConfigError> {
        self.validate()?;
        let mut config = ServerConfig::new(self.server.bind);
        config.pairing_ttl = Duration::from_secs(self.server.pairing_ttl_seconds);
        config.max_pairings = self.server.max_pairings;
        config.max_join_attempts = self.server.max_join_attempts;
        config.max_pending_messages = self.server.max_pending_messages;
        config.relay = RelayConfig {
            max_bytes_per_session: self.relay.max_bytes_per_session,
            max_bytes_total: self.relay.max_bytes_total,
            max_streams_per_session: self.relay.max_streams_per_session,
            buffer_size: self.relay.buffer_size,
        };
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.pairing_ttl_seconds == 0 {
            return Err(invalid("server.pairing_ttl_seconds 必须大于 0"));
        }
        if self.server.max_pairings == 0 {
            return Err(invalid("server.max_pairings 必须大于 0"));
        }
        if self.server.max_join_attempts == 0 {
            return Err(invalid("server.max_join_attempts 必须大于 0"));
        }
        if self.server.max_pending_messages == 0 {
            return Err(invalid("server.max_pending_messages 必须大于 0"));
        }
        if self.relay.max_streams_per_session == 0 {
            return Err(invalid("relay.max_streams_per_session 必须大于 0"));
        }
        if self.relay.buffer_size == 0 {
            return Err(invalid("relay.buffer_size 必须大于 0"));
        }
        Ok(())
    }

    fn apply_environment(&mut self) -> Result<(), ConfigError> {
        set_env_parse("UDP_FILE_SERVER_BIND", &mut self.server.bind)?;
        set_env_parse(
            "UDP_FILE_SERVER_PAIRING_TTL_SECONDS",
            &mut self.server.pairing_ttl_seconds,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_MAX_PAIRINGS",
            &mut self.server.max_pairings,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_MAX_JOIN_ATTEMPTS",
            &mut self.server.max_join_attempts,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_MAX_PENDING_MESSAGES",
            &mut self.server.max_pending_messages,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_RELAY_MAX_BYTES_PER_SESSION",
            &mut self.relay.max_bytes_per_session,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_RELAY_MAX_BYTES_TOTAL",
            &mut self.relay.max_bytes_total,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_RELAY_MAX_STREAMS_PER_SESSION",
            &mut self.relay.max_streams_per_session,
        )?;
        set_env_parse(
            "UDP_FILE_SERVER_RELAY_BUFFER_SIZE",
            &mut self.relay.buffer_size,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfigFile {
    /// 服务端 UDP 监听地址；端口为 0 时由系统分配。
    #[serde(alias = "endpoint")]
    pub bind: SocketAddr,
    pub pairing_ttl_seconds: u64,
    pub max_pairings: usize,
    pub max_join_attempts: usize,
    pub max_pending_messages: usize,
}

impl Default for ServerConfigFile {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND,
            pairing_ttl_seconds: 600,
            max_pairings: 1024,
            max_join_attempts: 8,
            max_pending_messages: 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfigFile {
    pub max_bytes_per_session: u64,
    pub max_bytes_total: u64,
    pub max_streams_per_session: usize,
    pub buffer_size: usize,
}

impl Default for RelayConfigFile {
    fn default() -> Self {
        let config = RelayConfig::default();
        Self {
            max_bytes_per_session: config.max_bytes_per_session,
            max_bytes_total: config.max_bytes_total,
            max_streams_per_session: config.max_streams_per_session,
            buffer_size: config.buffer_size,
        }
    }
}

fn set_env_parse<T>(name: &str, target: &mut T) -> Result<(), ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let Ok(value) = std::env::var(name) else {
        return Ok(());
    };
    *target = value
        .parse()
        .map_err(|error| invalid(format!("环境变量 {name} 的值 {value:?} 无法解析：{error}")))?;
    Ok(())
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_server_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.server.bind, DEFAULT_BIND);
        assert_eq!(config.server.pairing_ttl_seconds, 600);
        assert_eq!(config.relay.buffer_size, 64 * 1024);
    }

    #[test]
    fn toml_maps_nested_sections_and_endpoint_alias() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                endpoint = "192.0.2.10:42000"
                pairing_ttl_seconds = 120
                [relay]
                max_streams_per_session = 4
                buffer_size = 32768
            "#,
        )
        .expect("valid config");
        assert_eq!(config.server.bind, "192.0.2.10:42000".parse().unwrap());
        assert_eq!(config.server.pairing_ttl_seconds, 120);
        assert_eq!(config.relay.max_streams_per_session, 4);
        assert_eq!(config.relay.buffer_size, 32768);
    }

    #[test]
    fn cli_values_override_config() {
        let cli = Cli {
            config: None,
            bind: Some("127.0.0.1:0".parse().unwrap()),
            pairing_ttl_seconds: Some(30),
            max_pairings: Some(2),
            max_join_attempts: Some(3),
            max_pending_messages: Some(4),
            relay_max_bytes_per_session: Some(5),
            relay_max_bytes_total: Some(6),
            relay_max_streams_per_session: Some(7),
            relay_buffer_size: Some(8),
            log_level: "debug".to_owned(),
            command: None,
        };
        let mut config = AppConfig::default();
        config.apply_cli(&cli).expect("valid overrides");
        let server = config.server_config().expect("valid server config");
        assert_eq!(server.endpoint.bind_addr, "127.0.0.1:0".parse().unwrap());
        assert_eq!(server.pairing_ttl, Duration::from_secs(30));
        assert_eq!(server.max_pairings, 2);
        assert_eq!(server.relay.max_bytes_per_session, 5);
        assert_eq!(server.relay.buffer_size, 8);
    }
}
