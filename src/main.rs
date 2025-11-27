mod config;
mod models;
mod network;
mod blockchain;
mod crypto;
mod wallet;

use clap::Parser;
use std::{collections::btree_map::Range, error::Error};



use bls_bulletproofs::RangeProof;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 启动的角色名称
    #[arg(index = 1)]
    name: String,

    /// [新增] 初始锁币金额 (单位: wei)。例如: --deposit 100
    #[arg(short, long)]
    deposit: Option<u128>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    
    let config = config::load()?;
    let args = Args::parse();
    
    let target_name = args.name;
    // 获取命令行传入的金额 (可能是 Some(数值) 也可能是 None)
    let deposit_arg = args.deposit; 

    let rpc_url = config.rpc_url.clone();
    let contracts = config.contracts.clone();

    if target_name == config.operator.name {
        // 传入 deposit_arg
        network::operator::run(config.operator, rpc_url, contracts, deposit_arg).await?;
    } else {
        if let Some(user_conf) = config.users.iter().find(|u| u.name == target_name) {
            // 传入 deposit_arg
            network::user::run(user_conf.clone(), config.operator.clone(), rpc_url, contracts, deposit_arg).await?;
        } else {
            eprintln!("❌ 错误: 找不到用户: {}", target_name);
        }
    }

    Ok(())
}