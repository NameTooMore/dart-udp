use std::{error::Error, fmt, io};

use transfer_client::ClientError;

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "读取配置失败：{error}"),
            Self::Toml(error) => write!(f, "解析 TOML 失败：{error}"),
            Self::Invalid(message) => write!(f, "配置无效：{message}"),
        }
    }
}

impl Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Toml(error)
    }
}

#[derive(Debug)]
pub enum AppError {
    Config(ConfigError),
    Client(ClientError),
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Client(error) => write!(f, "传输失败：{error}"),
            Self::Io(error) => write!(f, "终端或文件操作失败：{error}"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl Error for AppError {}

impl From<ConfigError> for AppError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<ClientError> for AppError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
