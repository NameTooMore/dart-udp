use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use serde::Deserialize;
use transfer_client::{ClientConfig, ManifestBuildConfig, OverwritePolicy, SessionConfig};

use crate::{cli::Cli, error::ConfigError};

const DEFAULT_SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 41000);
const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub server: ServerConfigFile,
    pub client: ClientConfigFile,
    pub network: NetworkConfigFile,
    pub transfer: TransferConfigFile,
    pub storage: StorageConfigFile,
    pub ui: UiConfigFile,
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
        if let Some(server) = cli.server {
            self.server.endpoint = server;
        }
        if let Some(bind) = cli.bind {
            self.client.bind = bind;
        }
        if let Some(display_name) = &cli.display_name {
            self.client.display_name = display_name.clone();
        }
        if let Some(chunk_size) = cli.chunk_size {
            self.transfer.chunk_size = chunk_size;
        }
        if let Some(max_parallel_files) = cli.max_parallel_files {
            self.transfer.max_parallel_files = max_parallel_files;
        }
        if let Some(checkpoint_interval_bytes) = cli.checkpoint_interval_bytes {
            self.transfer.checkpoint_interval_bytes = checkpoint_interval_bytes;
        }
        if let Some(download_root) = &cli.download_root {
            self.storage.download_root = download_root.clone();
        }
        if cli.direct_only {
            self.network.direct_only = true;
        }
        if cli.no_direct {
            self.network.enable_direct = false;
        }
        if cli.no_color {
            self.ui.color = false;
        }
        if let Some(refresh_hz) = cli.refresh_hz {
            self.ui.refresh_hz = refresh_hz;
        }
        self.validate()
    }

    pub fn client_config(&self) -> Result<ClientConfig, ConfigError> {
        self.validate()?;
        let mut config = ClientConfig::new(self.server.endpoint);
        config.endpoint.bind_addr = self.client.bind;
        config.network.timeout = Duration::from_millis(self.network.probe_timeout_ms);
        config.network.retries = self.network.probe_retries;
        config.network.max_candidates = self.network.max_candidates;
        config.enable_direct = self.network.enable_direct;
        config.direct_only = self.network.direct_only;
        config.manifest = ManifestBuildConfig {
            max_file_size: self.transfer.max_file_size,
            max_total_size: self.transfer.max_total_size,
            ..ManifestBuildConfig::default()
        };
        config.session = SessionConfig {
            max_parallel_files: self.transfer.max_parallel_files,
            ..config.session
        };
        config.display_name = self.client.display_name.clone();
        config.chunk_size = self.transfer.chunk_size;
        config.checkpoint_interval_bytes = self.transfer.checkpoint_interval_bytes;
        Ok(config)
    }

    pub fn overwrite_policy(&self) -> Result<OverwritePolicy, ConfigError> {
        parse_overwrite(&self.transfer.overwrite)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.endpoint.port() == 0 {
            return Err(invalid("server.endpoint 不能使用 0 端口"));
        }
        if self.server.connect_timeout_ms == 0 {
            return Err(invalid("server.connect_timeout_ms 必须大于 0"));
        }
        if self.server.pairing_ttl_seconds == 0 {
            return Err(invalid("server.pairing_ttl_seconds 必须大于 0"));
        }
        if self.client.display_name.is_empty() {
            return Err(invalid("client.display_name 不能为空"));
        }
        if self.network.probe_timeout_ms == 0 {
            return Err(invalid("network.probe_timeout_ms 必须大于 0"));
        }
        if self.network.max_candidates == 0 {
            return Err(invalid("network.max_candidates 必须大于 0"));
        }
        if self.transfer.chunk_size == 0 || self.transfer.chunk_size > 1024 * 1024 {
            return Err(invalid("transfer.chunk_size 必须在 1..=1048576 范围内"));
        }
        if self.transfer.max_parallel_files == 0 {
            return Err(invalid("transfer.max_parallel_files 必须大于 0"));
        }
        if self.transfer.checkpoint_interval_bytes == 0
            || self.transfer.checkpoint_interval_seconds == 0
        {
            return Err(invalid("checkpoint interval 必须大于 0"));
        }
        if self.transfer.max_file_size == 0 || self.transfer.max_total_size == 0 {
            return Err(invalid("传输大小上限必须大于 0"));
        }
        if self.storage.allow_symlink {
            return Err(invalid(
                "storage.allow_symlink=true 当前不受 transfer-client 支持；为安全起见已拒绝",
            ));
        }
        if self.ui.refresh_hz == 0 {
            return Err(invalid("ui.refresh_hz 必须大于 0"));
        }
        parse_overwrite(&self.transfer.overwrite)?;
        Ok(())
    }

    fn apply_environment(&mut self) -> Result<(), ConfigError> {
        set_env_parse("UDP_FILE_SERVER_ENDPOINT", &mut self.server.endpoint)?;
        set_env_parse(
            "UDP_FILE_SERVER_PAIRING_TTL_SECONDS",
            &mut self.server.pairing_ttl_seconds,
        )?;
        set_env_parse("UDP_FILE_CLIENT_BIND", &mut self.client.bind)?;
        set_env_string(
            "UDP_FILE_CLIENT_DISPLAY_NAME",
            &mut self.client.display_name,
        );
        set_env_parse(
            "UDP_FILE_NETWORK_ENABLE_DIRECT",
            &mut self.network.enable_direct,
        )?;
        set_env_parse(
            "UDP_FILE_NETWORK_DIRECT_ONLY",
            &mut self.network.direct_only,
        )?;
        set_env_parse(
            "UDP_FILE_NETWORK_PROBE_TIMEOUT_MS",
            &mut self.network.probe_timeout_ms,
        )?;
        set_env_parse(
            "UDP_FILE_NETWORK_PROBE_RETRIES",
            &mut self.network.probe_retries,
        )?;
        set_env_parse(
            "UDP_FILE_NETWORK_MAX_CANDIDATES",
            &mut self.network.max_candidates,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_CHUNK_SIZE",
            &mut self.transfer.chunk_size,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_MAX_PARALLEL_FILES",
            &mut self.transfer.max_parallel_files,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_CHECKPOINT_INTERVAL_BYTES",
            &mut self.transfer.checkpoint_interval_bytes,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_CHECKPOINT_INTERVAL_SECONDS",
            &mut self.transfer.checkpoint_interval_seconds,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_MAX_FILE_SIZE",
            &mut self.transfer.max_file_size,
        )?;
        set_env_parse(
            "UDP_FILE_TRANSFER_MAX_TOTAL_SIZE",
            &mut self.transfer.max_total_size,
        )?;
        set_env_string("UDP_FILE_TRANSFER_OVERWRITE", &mut self.transfer.overwrite);
        if let Some(root) = std::env::var_os("UDP_FILE_STORAGE_DOWNLOAD_ROOT") {
            self.storage.download_root = PathBuf::from(root);
        }
        set_env_parse("UDP_FILE_STORAGE_SYNC_DATA", &mut self.storage.sync_data)?;
        set_env_parse("UDP_FILE_STORAGE_SYNC_ALL", &mut self.storage.sync_all)?;
        set_env_parse("UDP_FILE_UI_COLOR", &mut self.ui.color)?;
        set_env_parse("UDP_FILE_UI_REFRESH_HZ", &mut self.ui.refresh_hz)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfigFile {
    pub endpoint: SocketAddr,
    pub connect_timeout_ms: u64,
    pub pairing_ttl_seconds: u32,
}

impl Default for ServerConfigFile {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_SERVER,
            connect_timeout_ms: 5_000,
            pairing_ttl_seconds: 600,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfigFile {
    pub bind: SocketAddr,
    pub display_name: String,
}

impl Default for ClientConfigFile {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND,
            display_name: "udp-file-client".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfigFile {
    pub enable_direct: bool,
    pub direct_only: bool,
    pub probe_timeout_ms: u64,
    pub probe_retries: usize,
    pub max_candidates: usize,
    pub keep_relay_warm: bool,
}

impl Default for NetworkConfigFile {
    fn default() -> Self {
        Self {
            enable_direct: true,
            direct_only: false,
            probe_timeout_ms: 1_500,
            probe_retries: 3,
            max_candidates: 16,
            keep_relay_warm: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferConfigFile {
    pub chunk_size: usize,
    pub max_parallel_files: usize,
    pub checkpoint_interval_bytes: u64,
    pub checkpoint_interval_seconds: u64,
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub overwrite: String,
}

impl Default for TransferConfigFile {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024,
            max_parallel_files: 2,
            checkpoint_interval_bytes: 4 * 1024 * 1024,
            checkpoint_interval_seconds: 2,
            max_file_size: 1024 * 1024 * 1024 * 1024,
            max_total_size: 4 * 1024 * 1024 * 1024 * 1024,
            overwrite: "ask".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfigFile {
    pub download_root: PathBuf,
    pub allow_symlink: bool,
    pub sync_data: bool,
    pub sync_all: bool,
}

impl Default for StorageConfigFile {
    fn default() -> Self {
        Self {
            download_root: PathBuf::from("./downloads"),
            allow_symlink: false,
            sync_data: true,
            sync_all: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfigFile {
    pub color: bool,
    pub refresh_hz: u16,
}

impl Default for UiConfigFile {
    fn default() -> Self {
        Self {
            color: true,
            refresh_hz: 10,
        }
    }
}

fn parse_overwrite(value: &str) -> Result<OverwritePolicy, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "ask" => Ok(OverwritePolicy::Ask),
        "no-replace" | "noreplace" => Ok(OverwritePolicy::NoReplace),
        "replace" | "replace-after-confirm" => Ok(OverwritePolicy::ReplaceAfterConfirm),
        "rename" | "rename-with-suffix" => Ok(OverwritePolicy::RenameWithSuffix),
        _ => Err(invalid(format!("transfer.overwrite 不支持值 {value:?}"))),
    }
}

fn set_env_string(name: &str, target: &mut String) {
    if let Ok(value) = std::env::var(name) {
        *target = value;
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
    fn default_config_matches_documented_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.server.endpoint, DEFAULT_SERVER);
        assert_eq!(config.transfer.chunk_size, 1024 * 1024);
        assert_eq!(config.ui.refresh_hz, 10);
    }

    #[test]
    fn toml_maps_nested_sections() {
        let config: AppConfig = toml::from_str(
            r#"
                [server]
                endpoint = "192.0.2.10:42000"
                [network]
                direct_only = true
                [storage]
                download_root = "./out"
            "#,
        )
        .expect("valid config");
        assert_eq!(config.server.endpoint, "192.0.2.10:42000".parse().unwrap());
        assert!(config.network.direct_only);
        assert_eq!(config.storage.download_root, PathBuf::from("./out"));
    }
}
