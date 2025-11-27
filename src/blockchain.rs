use crate::config::ActorConfig;
use alloy::{
    network::EthereumWallet,
    // [修复] 在这里添加 Bytes
    primitives::{Address, U256, FixedBytes, Bytes}, 
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use std::error::Error;
use std::str::FromStr;
use url::Url;

// 加载 ABI (现在包含了 createChannel)
sol!(
    #[sol(rpc)]
    Channel,
    "abi/Channel.json"
);

// 1. 锁币函数 (保持不变，为了完整性我贴在这里)
pub async fn lock_deposit(
    actor: &ActorConfig, 
    rpc_url: &str, 
    contract_address: Address,
    amount_wei: u128 
) -> Result<(), Box<dyn Error>> {
    println!("🔗 [{}] 正在连接区块链...", actor.name);
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_address, provider.clone());
    let amount = U256::from(amount_wei);

    println!("💰 [{}] 准备锁币: {} wei 到合约 {:?}", actor.name, amount_wei, contract_address);
    let tx_builder = contract.lockDeposit().value(amount);
    let receipt = tx_builder.send().await?.get_receipt().await?;
    println!("✅ [{}] 锁币成功！Tx: {}", actor.name, receipt.transaction_hash);
    Ok(())
}

// 2. [新增] 创建通道函数
pub async fn create_channel(
    actor: &ActorConfig,
    rpc_url: &str,
    contract_address: Address,
    channel_id: FixedBytes<32> // Solidity 的 bytes32 对应 Rust 的 FixedBytes<32>
) -> Result<String, Box<dyn Error>> {
    // 设置 Provider
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).on_http(Url::parse(rpc_url)?);
    
    // 实例化合约
    let contract = Channel::new(contract_address, provider);

    // 调用 createChannel
    // 注意：createChannel 是 non-payable 的，不需要 .value()
    let tx_builder = contract.createChannel(channel_id);
    
    // 发送并等待回执
    let receipt = tx_builder.send().await?.get_receipt().await?;
    
    // 返回交易哈希字符串
    Ok(receipt.transaction_hash.to_string())
}

// [新增] 1. Operator 上传 RSUC 参数
pub async fn setup_rsuc(
    actor: &ActorConfig,
    rpc_url: &str,
    contract_addr: Address,
    channel_id: FixedBytes<32>,
    g1: Vec<u8>, p: Vec<u8>, g2: Vec<u8>, ord: Vec<u8>, vk: Vec<u8>
) -> Result<String, Box<dyn Error>> {
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let provider = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_addr, provider);

    // 调用 setupRSUC (注意参数类型转换)
    let tx = contract.setupRSUC(
        channel_id, Bytes::from(g1), Bytes::from(p), Bytes::from(g2), Bytes::from(ord), Bytes::from(vk)
    );
    let receipt = tx.send().await?.get_receipt().await?;
    Ok(receipt.transaction_hash.to_string())
}

// [新增] 2. User 获取 RSUC 参数
// 返回 (G1, P, G2, Ord, Vk) 的字节数组元组
pub async fn get_rsuc_info(
    rpc_url: &str,
    contract_addr: Address,
    channel_id: FixedBytes<32>
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let provider = ProviderBuilder::new().on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_addr, provider);
    
    let result = contract.getRSUCInfo(channel_id).call().await?;
    // result 是一个生成的结构体/元组，包含 returns 里的字段
    Ok((
        result.G1.to_vec(), 
        result.P.to_vec(), 
        result.G2.to_vec(), 
        result.curveOrder.to_vec(), 
        result.vk.to_vec()
    ))
}