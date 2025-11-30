use crate::config::ActorConfig;
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, FixedBytes, Bytes}, 
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use std::error::Error;
use std::str::FromStr;
use url::Url;

// 加载 ABI
sol!(
    #[sol(rpc)]
    Channel,
    "abi/Channel.json"
);

// 1. 锁币函数 (用户/Operator 调用)
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

// 2. 创建通道 (Operator 调用)
pub async fn create_channel(
    actor: &ActorConfig,
    rpc_url: &str,
    contract_address: Address,
    channel_id: FixedBytes<32> 
) -> Result<String, Box<dyn Error>> {
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let provider = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_address, provider);

    let tx_builder = contract.createChannel(channel_id);
    let receipt = tx_builder.send().await?.get_receipt().await?;
    Ok(receipt.transaction_hash.to_string())
}

// 3. 上传 RSUC 参数 (Operator 调用)
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

    let tx = contract.setupRSUC(
        channel_id, Bytes::from(g1), Bytes::from(p), Bytes::from(g2), Bytes::from(ord), Bytes::from(vk)
    );
    let receipt = tx.send().await?.get_receipt().await?;
    Ok(receipt.transaction_hash.to_string())
}

// 4. 获取 RSUC 参数 (User 调用)
pub async fn get_rsuc_info(
    rpc_url: &str,
    contract_addr: Address,
    channel_id: FixedBytes<32>
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let provider = ProviderBuilder::new().on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_addr, provider);
    
    let result = contract.getRSUCInfo(channel_id).call().await?;
    Ok((
        result.G1.to_vec(), 
        result.P.to_vec(), 
        result.G2.to_vec(), 
        result.curveOrder.to_vec(), 
        result.vk.to_vec()
    ))
}

// [新增] 5. 用户加入通道 (Operator 调用)
// Operator 在链下验证完 Join 请求后，调用此函数在链上登记
pub async fn join_channel(
    actor: &ActorConfig,
    rpc_url: &str,
    contract_addr: Address,
    channel_id: FixedBytes<32>,
    user_addr: Address
) -> Result<String, Box<dyn Error>> {
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let provider = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_addr, provider);

    let tx = contract.joinChannel(channel_id, user_addr);
    let receipt = tx.send().await?.get_receipt().await?;
    Ok(receipt.transaction_hash.to_string())
}

// [新增] 6. Operator 授权提现 (Operator 调用)
// Operator 验证完 Exit 请求和余额后，调用此函数给用户转账
pub async fn operator_withdraw(
    actor: &ActorConfig,
    rpc_url: &str,
    contract_addr: Address,
    channel_id: FixedBytes<32>,
    user_addr: Address,
    amount_wei: u128
) -> Result<String, Box<dyn Error>> {
    let signer: PrivateKeySigner = actor.private_key.parse()?;
    let provider = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).on_http(Url::parse(rpc_url)?);
    let contract = Channel::new(contract_addr, provider);

    let amount = U256::from(amount_wei);
    
    let tx = contract.operatorWithdraw(channel_id, user_addr, amount);
    let receipt = tx.send().await?.get_receipt().await?;
    Ok(receipt.transaction_hash.to_string())
}