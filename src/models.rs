use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub r#type: String,
    pub sender: String,
    
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,

    // === Join 相关 ===
    #[serde(default)]
    pub amount: Option<String>,     // Hex string
    #[serde(default)]
    pub vk: Option<String>,         // Schnorr Public Key (Base64)
    #[serde(default)]
    pub commitment: Option<String>, // Base64 (C)
    #[serde(default)]
    pub signature: Option<String>,  // Base64 (Sigma)
    #[serde(default)]
    pub cipher_r: Option<String>,   // Base64 (Encrypted r)

    // === 广播相关 ===
    #[serde(default)]
    pub content: Option<String>,    // 状态字符串
}

impl Message {
    pub fn new(t: &str, sender: &str) -> Self {
        Self {
            r#type: t.to_string(),
            sender: sender.to_string(),
            request_id: Some(uuid::Uuid::new_v4().to_string()[0..8].to_string()),
            channel_id: None, amount: None, vk: None,
            commitment: None, signature: None, cipher_r: None, content: None,
        }
    }
}