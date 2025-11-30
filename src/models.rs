use serde::{Deserialize, Serialize};
// [修复] 删除了 use crate::models::EpochUpdateItem; 这一行

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub r#type: String,
    pub sender: String,
    
    #[serde(default)] pub channel_id: Option<String>,
    #[serde(default)] pub request_id: Option<String>,
    
    // Join & Common
    #[serde(default)] pub amount: Option<String>,
    #[serde(default)] pub vk: Option<String>,
    #[serde(default)] pub commitment: Option<String>,
    #[serde(default)] pub signature: Option<String>,
    #[serde(default)] pub cipher_r: Option<String>,
    #[serde(default)] pub content: Option<String>,

    // Update
    #[serde(default)] pub tx_data: Option<String>,
    #[serde(default)] pub schnorr_sig: Option<String>,
    #[serde(default)] pub sender_commitment: Option<String>,
    #[serde(default)] pub sender_zk_sig: Option<String>,
    #[serde(default)] pub receiver_commitment: Option<String>,
    #[serde(default)] pub receiver_zk_sig: Option<String>,

    // Epoch 相关
    #[serde(default)] pub epoch_updates: Option<Vec<EpochUpdateItem>>,
    #[serde(default)] pub epoch_round: Option<u64>,

    // Exit 相关
    #[serde(default)] pub r_reveal: Option<String>, 
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
            epoch_updates: None, epoch_round: None,
            r_reveal: None,
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

// Epoch 汇报条目
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EpochUpdateItem {
    pub commitment: String, 
    pub signature: String,  
    pub amount_hex: String,
}