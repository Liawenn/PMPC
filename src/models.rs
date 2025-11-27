use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub r#type: String,
    pub sender: String,
    
    #[serde(default)] pub channel_id: Option<String>,
    #[serde(default)] pub request_id: Option<String>,
    #[serde(default)] pub amount: Option<String>,
    #[serde(default)] pub vk: Option<String>,
    #[serde(default)] pub commitment: Option<String>,
    #[serde(default)] pub signature: Option<String>,
    #[serde(default)] pub cipher_r: Option<String>,
    #[serde(default)] pub content: Option<String>,

    // === 交易/P2P 相关 ===
    #[serde(default)] pub tx_data: Option<String>,   
    #[serde(default)] pub schnorr_sig: Option<String>, 
    
    // === Update 结果 ===
    #[serde(default)] pub sender_commitment: Option<String>,
    #[serde(default)] pub sender_zk_sig: Option<String>,
    #[serde(default)] pub receiver_commitment: Option<String>,
    #[serde(default)] pub receiver_zk_sig: Option<String>,
}

impl Message {
    pub fn new(t: &str, sender: &str) -> Self {
        Self {
            r#type: t.to_string(),
            sender: sender.to_string(),
            request_id: Some(uuid::Uuid::new_v4().to_string()[0..8].to_string()),
            channel_id: None, amount: None, vk: None,
            commitment: None, signature: None, cipher_r: None, content: None,
            tx_data: None, schnorr_sig: None,
            sender_commitment: None, sender_zk_sig: None,
            receiver_commitment: None, receiver_zk_sig: None,
        }
    }
}

// 交易结构体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionTx {
    pub sender_commitment: String,
    pub sender_zk_sig: String,
    pub receiver_commitment: String,
    pub receiver_zk_sig: String,
    pub amount: String,
    pub range_proof: String,
    pub range_com: String, 
    pub timestamp: u64,
}