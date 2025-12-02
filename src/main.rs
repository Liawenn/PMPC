mod config;
mod models;
mod network;
mod blockchain;
mod crypto;
mod wallet;

use clap::Parser;
use std::error::Error;
// use bls_bulletproofs::RangeProof; // 如果没用到可以注释掉

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 启动的角色名称
    #[arg(index = 1)]
    name: String,

    /// [可选] 初始锁币金额 (单位: wei)。
    /// 仅 Operator 有效。如果设置，将在创建通道前执行充值。
    /// 例如: --deposit 100
    #[arg(short, long)]
    deposit: Option<u128>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. 加载配置
    let config = config::load()?;
    let args = Args::parse();
    
    let target_name = args.name;
    let deposit_arg = args.deposit; 

    let rpc_url = config.rpc_url.clone();
    let contracts = config.contracts.clone();

    // 2. 判断角色
    if target_name == config.operator.name {
        println!("🚀 启动 Operator 流程...");
        
        // Operator 强依赖合约配置，这里做一个安全检查
        let contracts_conf = contracts.as_ref()
            .ok_or("❌ 错误: Operator 模式需要在配置文件中指定 contracts 地址")?;

        // ------------------------------------------------------------------
        // Phase 0: 资金预存 (Fund) - 可选
        // ------------------------------------------------------------------
        if let Some(amount) = deposit_arg {
            if amount > 0 {
                network::operator::fund_operator(
                    &config.operator, 
                    &rpc_url, 
                    contracts_conf, 
                    amount
                ).await?;
            } else {
                println!("ℹ️  检测到 --deposit 0，跳过充值步骤");
            }
        }

        // ------------------------------------------------------------------
        // Phase 1: 创建通道 (Create) - 极速链上注册
        // ------------------------------------------------------------------
        // 返回通道的字符串ID和Hex ID
        let (chan_id_str, chan_id_bytes) = network::operator::create_channel(
            &config.operator, 
            &rpc_url, 
            contracts_conf
        ).await?;

        // ------------------------------------------------------------------
        // Phase 2: 初始化参数 (Init) - 耗时计算与上传
        // ------------------------------------------------------------------
        // 返回包含所有上下文的 shared state
        let state = network::operator::init_channel(
            &config.operator,
            &rpc_url,
            contracts_conf,
            chan_id_str,
            chan_id_bytes
        ).await?;

        // ------------------------------------------------------------------
        // Phase 3: 启动服务 (Run) - 阻塞运行
        // ------------------------------------------------------------------
        network::operator::run_node(
            state, 
            config.operator, 
            rpc_url, 
            contracts // run_node 内部接受 Option<ContractsConfig>
        ).await?;

    } else {
        // 3. User 流程 (保持原有逻辑)
        if let Some(user_conf) = config.users.iter().find(|u| u.name == target_name) {
            // 注意：如果 user::run 没改，这里保持原样；
            // 如果 user::run 不需要 deposit_arg 了，请记得在 user.rs 里也把参数去掉
            network::user::run(
                user_conf.clone(), 
                config.operator.clone(), 
                rpc_url, 
                contracts, 
                deposit_arg
            ).await?;
        } else {
            eprintln!("❌ 错误: 找不到用户: {}", target_name);
        }
    }

    Ok(())
}