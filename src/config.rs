use alloy::primitives::Address;
use serde::Deserialize;
use std::fs;
use std::error::Error;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub rpc_url: String,
    pub operator: ActorConfig,
    pub users: Vec<ActorConfig>,
    pub contracts: Option<ContractsConfig>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct ActorConfig {
    pub name: String,
    pub private_key: String,
    pub address: Address,
    // [修改] 改为 Option，因为 Operator 可能不配这两个
    pub host: Option<String>, 
    pub port: Option<u16>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct ContractsConfig {
    pub payment_channel: Address,
}

pub fn load() -> Result<AppConfig, Box<dyn Error>> {
    let content = fs::read_to_string("config.toml")
        .map_err(|_| "❌ 找不到 config.toml，请确保它在项目根目录！")?;
    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| format!("❌ 配置文件解析错误: {}", e))?;
    Ok(config)
}