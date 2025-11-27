use crate::config::{ActorConfig, ContractsConfig, AppConfig};
use crate::models::{Message, TransactionTx};
use crate::wallet::UserWallet;
use crate::blockchain;
use crate::crypto::RSUC::{self, PP, AuthCommitment}; 
use crate::crypto::RSUC::wrapper::{Fr, G1, G2};
use crate::crypto::RSUC::utils::{
    ecp_from_base64, zksig_from_base64, ecp2_from_base64, 
    ecp_to_base64, zksig_to_base64, ecp2_to_base64,
    hash256, recover_r_from_bytes
};
use crate::crypto::{schnorr, range_proof};

use std::error::Error;
use zeromq::{Socket, SocketSend, SocketRecv};
use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use alloy::primitives::{FixedBytes, U256};
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

// --- UX 辅助函数 ---
fn print_menu() {
    println!("\n==============================================================");
    println!("  命令列表:");
    println!("  1. join <hex_id>           - 加入通道 (需复制 Operator 生成的 ID)");
    println!("  2. share_addr <target>     - P2P 分享收款地址给对方 (例如: share_addr Bob)");
    println!("  3. send <amount> <target>  - 发起隐私转账 (例如: send 5 Bob)");
    println!("  4. epoch                   - 结束当前 Epoch 并结算余额");
    println!("  5. balance                 - 查看本地余额和状态");
    println!("  6. help                    - 显示此菜单");
    println!("  7. exit                    - 退出客户端");
    println!("==============================================================\n");
}

fn print_prompt(name: &str) {
    print!("{}> ", name);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

// P2P 发送辅助函数
async fn p2p_send(host: &str, port: u16, msg: &Message) -> Result<(), Box<dyn Error>> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).await?;
    let json = serde_json::to_string(msg)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?; 
    Ok(())
}

pub async fn run(
    me: ActorConfig, 
    op: ActorConfig, 
    rpc_url: String, 
    contracts: Option<ContractsConfig>,
    initial_deposit: Option<u128>
) -> Result<(), Box<dyn Error>> {
    let full_config = crate::config::load().expect("无法读取Config用于P2P查询");

    println!("\n=== USER 启动 ===");
    println!("👤 身份: {}", me.name);

    if let Some(conf) = &contracts {
        if let Some(amt) = initial_deposit {
             let _ = blockchain::lock_deposit(&me, &rpc_url, conf.payment_channel, amt).await;
        }
    }

    let wallet = Arc::new(Mutex::new(UserWallet::new(initial_deposit.unwrap_or(0))));

    // Dealer 连接
    let mut dealer = zeromq::DealerSocket::new();
    let op_host = op.host.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let op_port = op.port.unwrap_or(5555);
    let op_addr = format!("tcp://{}:{}", op_host, op_port);
    dealer.connect(&op_addr).await?;
    
    // Sub 连接 (广播)
    let mut sub = zeromq::SubSocket::new();
    sub.connect(&format!("tcp://{}:5556", op_host)).await?;

    // P2P 监听
    let p2p_port = me.port.unwrap_or(6000);
    let p2p_listener = TcpListener::bind(format!("0.0.0.0:{}", p2p_port)).await?;

    let wallet_p2p = wallet.clone();
    
    // P2P 后台任务
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = p2p_listener.accept().await {
                let w = wallet_p2p.clone();
                tokio::spawn(async move {
                    let mut buf_reader = BufReader::new(&mut socket);
                    let mut line = String::new();
                    if let Ok(_) = buf_reader.read_line(&mut line).await {
                        if let Ok(msg) = serde_json::from_str::<Message>(&line) {
                            if msg.r#type == "EXCHANGE_INFO" {
                                println!("\n\n[P2P] 收到 {} 的地址信息", msg.sender);
                                if let (Some(c_str), Some(sig_str)) = (msg.commitment, msg.signature) {
                                    if let (Ok(c), Ok(sig)) = (ecp_from_base64(&c_str), zksig_from_base64(&sig_str)) {
                                        let ac = AuthCommitment { c, sigma: sig };
                                        w.lock().unwrap().peer_receptions.insert(msg.sender.clone(), ac);
                                        println!("✅ 已缓存 {} 的接收地址", msg.sender);
                                        print!("(按回车恢复提示符...) "); 
                                        use std::io::Write; let _ = std::io::stdout().flush();
                                    }
                                }
                            } else if msg.r#type == "FWD_UPDATE" {
                                println!("\n\n======== [P2P] 收到转账通知 (Epoch Pending) ========");
                                println!("来自: {} | 金额: {} (Hex)", msg.sender, msg.amount.clone().unwrap_or("?".into()));
                                
                                if let (Some(c_str), Some(sig_str)) = (msg.commitment, msg.signature) {
                                    if let (Ok(c), Ok(sig)) = (ecp_from_base64(&c_str), zksig_from_base64(&sig_str)) {
                                        println!("    > Updated Com: {}", c_str);
                                        let new_ac = AuthCommitment { c, sigma: sig };
                                        let amt = u64::from_str_radix(&msg.amount.unwrap(), 16).unwrap_or(0);
                                        
                                        let mut wallet_lock = w.lock().unwrap();
                                        let new_pending = wallet_lock.pending_amount + U256::from(amt);
                                        
                                        if let Some(ref mut base) = wallet_lock.base {
                                            base.ac = new_ac; 
                                        }
                                        wallet_lock.pending_amount = new_pending;
                                        
                                        println!("💰 收款暂存! Pending: {} wei (主余额: {})", new_pending, wallet_lock.amount);
                                        print!("(按回车恢复提示符...) ");
                                        use std::io::Write; let _ = std::io::stdout().flush();
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    let mut pp: Option<PP> = None;
    let mut cached_op_vk: Option<G2> = None; 
    let mut assigned_channel_id: Option<String> = None;

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    
    println!("\n{} 准备就绪.", me.name);
    print_menu(); 
    print_prompt(&me.name); 

    loop {
        tokio::select! {
            // --- 1. 键盘输入 ---
            line = stdin.next_line() => {
                if let Ok(Some(cmd_str)) = line {
                    let parts: Vec<&str> = cmd_str.trim().split_whitespace().collect();
                    if parts.is_empty() { print_prompt(&me.name); continue; }

                    match parts[0] {
                        "join" => {
                            if parts.len() < 2 { println!("❌ 用法: join <hex_id>"); print_prompt(&me.name); continue; }
                            let ch_id = parts[1];
                            assigned_channel_id = Some(ch_id.to_string());
                            // 订阅广播
                            sub.subscribe(ch_id).await?;
                            
                            let ch_id_bytes = match FixedBytes::<32>::from_str(ch_id) {
                                Ok(b) => b,
                                Err(_) => { println!("❌ Hex ID 格式错误"); print_prompt(&me.name); continue; }
                            };
                            
                            if let Some(conf) = &contracts {
                                match blockchain::get_rsuc_info(&rpc_url, conf.payment_channel, ch_id_bytes).await {
                                    Ok((g1_b, p_b, g2_b, _, vk_b)) => {
                                        let g1 = G1::from_hex(&hex::encode(g1_b)).unwrap();
                                        let p  = G1::from_hex(&hex::encode(p_b)).unwrap();
                                        let g2 = G2::from_hex(&hex::encode(g2_b)).unwrap();
                                        let vk = G2::from_hex(&hex::encode(vk_b)).unwrap();
                                        cached_op_vk = Some(vk);
                                        pp = Some(PP { g1, p, g2 });
                                        println!("[INFO] RSUC 参数加载成功");
                                    },
                                    Err(_) => { pp = Some(RSUC::setup()); cached_op_vk = Some(G2::generator()); }
                                }
                            } else { pp = Some(RSUC::setup()); cached_op_vk = Some(G2::generator()); }

                            let temp_pp = pp.as_ref().unwrap();
                            let pk = wallet.lock().unwrap().gen_schnorr_keys(temp_pp);
                            let cur_amt = wallet.lock().unwrap().amount;
                            
                            let mut req = Message::new("JOIN_REQ", &me.name);
                            req.channel_id = Some(ch_id.to_string());
                            req.amount = Some(format!("{:x}", cur_amt)); 
                            req.vk = Some(ecp_to_base64(pk)); 

                            let mut z = zeromq::ZmqMessage::from(vec![]);
                            z.push_back(serde_json::to_string(&req)?.into());
                            dealer.send(z).await?;
                            println!("[INFO] JOIN 发送中...");
                        },
                        "share_addr" => {
                            if parts.len() < 2 { println!("❌ 用法: share_addr <target_name>"); print_prompt(&me.name); continue; }
                            let target_name = parts[1];
                            if let Some(port) = full_config.get_user_port(target_name) {
                                let host = full_config.get_user_host(target_name).unwrap();
                                let mut w = wallet.lock().unwrap();
                                if let Some(pp_ref) = &pp {
                                    let _r_delta = w.prepare_reception_for_sharing(pp_ref);
                                    let recv_state = w.reception.as_ref().unwrap();
                                    
                                    let mut m = Message::new("EXCHANGE_INFO", &me.name);
                                    m.commitment = Some(ecp_to_base64(recv_state.ac.c));
                                    m.signature = Some(zksig_to_base64(&recv_state.ac.sigma));
                                    
                                    drop(w); 
                                    if let Err(e) = p2p_send(&host, port, &m).await {
                                        println!("❌ P2P 发送失败: {}", e);
                                    } else {
                                        println!("[P2P] 已发送接收地址给 {} ({}:{})", target_name, host, port);
                                    }
                                } else { println!("❌ 请先 Join"); }
                            } else { println!("❌ 找不到用户 {}", target_name); }
                            print_prompt(&me.name);
                        },
                        "send" => {
                            if parts.len() < 3 { println!("❌ 用法: send <amount> <target>"); print_prompt(&me.name); continue; }
                            let amt_u64: u64 = parts[1].parse().unwrap_or(0);
                            let target = parts[2];
                            
                            let mut w = wallet.lock().unwrap();
                            if !w.peer_receptions.contains_key(target) {
                                println!("❌ 无目标地址，请先: share_addr {}", target); 
                                print_prompt(&me.name);
                                continue; 
                            }
                            let recv_ac = w.peer_receptions.get(target).unwrap().clone();
                            let amt_u256 = U256::from(amt_u64);
                            
                            if w.pending_amount < amt_u256 { 
                                println!("❌ 余额不足 (Pending: {}, 需: {})", w.pending_amount, amt_u256); 
                                print_prompt(&me.name);
                                continue; 
                            }
                            let remaining = (w.pending_amount - amt_u256).to::<u64>(); 
                            
                            println!("⏳ 生成区间证明 ({} -> {})...", w.pending_amount, remaining);
                            let (proof_b64, com_b64) = range_proof::generate_proof(remaining).unwrap();
                            
                            let base_ac = &w.base.as_ref().unwrap().ac;
                            println!("    > Sender Base C: {}", ecp_to_base64(base_ac.c));
                            println!("    > Receiver Rand C: {}", ecp_to_base64(recv_ac.c));

                            let tx = TransactionTx {
                                sender_commitment: ecp_to_base64(base_ac.c),
                                sender_zk_sig: zksig_to_base64(&base_ac.sigma),
                                receiver_commitment: ecp_to_base64(recv_ac.c),
                                receiver_zk_sig: zksig_to_base64(&recv_ac.sigma),
                                amount: format!("{:x}", amt_u64),
                                range_proof: proof_b64,
                                range_com: com_b64,
                                timestamp: 0,
                            };
                            let tx_json = serde_json::to_string(&tx)?;
                            
                            let sk = w.schnorr_sk.unwrap(); 
                            let sig = schnorr::sign(&tx_json, sk, pp.as_ref().unwrap().g1);
                            
                            let mut req = Message::new("UPDATE_REQ", &me.name);
                            req.channel_id = assigned_channel_id.clone();
                            req.tx_data = Some(tx_json);
                            req.schnorr_sig = Some(schnorr::sig_to_base64(&sig));
                            req.content = Some(target.to_string());
                            
                            drop(w);
                            let mut z = zeromq::ZmqMessage::from(vec![]);
                            z.push_back(serde_json::to_string(&req)?.into());
                            dealer.send(z).await?;
                            println!("[INFO] 交易请求已发送 (ID: {}, Target: {})", req.request_id.unwrap(), target);
                        },
                        "epoch" => {
                            let mut w = wallet.lock().unwrap();
                            w.end_epoch();
                            print_prompt(&me.name);
                        },
                        "balance" => {
                            let w = wallet.lock().unwrap();
                            println!("\n💰 当前状态:");
                            println!("   主余额 (On-Chain/Settled): {} wei", w.amount);
                            println!("   Pending 余额 (Current Epoch): {} wei", w.pending_amount);
                            println!("   P2P 缓存: {:?}", w.peer_receptions.keys().collect::<Vec<_>>());
                            println!("   Join 状态: {}", if pp.is_some() { "✅ 已加入" } else { "❌ 未加入" });
                            print_prompt(&me.name);
                        },
                        "help" => {
                            print_menu();
                            print_prompt(&me.name);
                        },
                        "exit" => break,
                        _ => {
                            println!("❌ 未知命令");
                            print_prompt(&me.name);
                        },
                    }
                }
            }

            // --- 2. Dealer 消息 (OK_JOIN, OK_UPDATE) ---
            msg = dealer.recv() => {
                if let Ok(m) = msg {
                    if let Some(payload) = m.iter().last() {
                        let json = String::from_utf8_lossy(payload);
                        if let Ok(resp) = serde_json::from_str::<Message>(&json) {
                            if resp.r#type == "OK_JOIN" {
                                let local_pp = pp.as_ref().unwrap();
                                let c = ecp_from_base64(&resp.commitment.unwrap()).unwrap();
                                let sigma = zksig_from_base64(&resp.signature.unwrap()).unwrap();
                                let cipher = general_purpose::STANDARD.decode(resp.cipher_r.unwrap()).unwrap();
                                let chain_vk = cached_op_vk.unwrap();
                                let vk_b64 = ecp2_to_base64(chain_vk);
                                let key = hash256(format!("{}{}", vk_b64, me.name).as_bytes());
                                let mut r_bytes = vec![0u8; cipher.len()];
                                for i in 0..cipher.len() { r_bytes[i] = cipher[i] ^ key[i % key.len()]; }
                                let r = recover_r_from_bytes(&r_bytes);
                                let ac = AuthCommitment { c, sigma };
                                wallet.lock().unwrap().init_from_operator(ac, r, local_pp);
                                println!("[SUCCESS] 加入成功！");
                                print_prompt(&me.name); 

                            } else if resp.r#type == "OK_UPDATE" {
                                println!("\n======== [收到交易确认] ========");
                                let c = ecp_from_base64(&resp.sender_commitment.unwrap())?;
                                let sigma = zksig_from_base64(&resp.sender_zk_sig.unwrap())?;
                                let new_ac = AuthCommitment { c, sigma };
                                let amt = u64::from_str_radix(&resp.amount.unwrap(), 16)?;
                                let target_name = resp.content.unwrap_or("Unknown".into());

                                let mut w = wallet.lock().unwrap();
                                // 更新 pending
                                let new_pending = w.pending_amount - U256::from(amt);
                                w.apply_update_pending(new_ac, new_pending, pp.as_ref().unwrap());
                                
                                // P2P 转发
                                if let Some(port) = full_config.get_user_port(&target_name) {
                                    let host = full_config.get_user_host(&target_name).unwrap();
                                    let mut fwd = Message::new("FWD_UPDATE", &me.name);
                                    fwd.amount = Some(format!("{:x}", amt));
                                    fwd.commitment = resp.receiver_commitment; 
                                    fwd.signature = resp.receiver_zk_sig;
                                    drop(w);
                                    p2p_send(&host, port, &fwd).await?;
                                    println!("🔄 转发凭证给: {}", target_name);
                                }
                                print_prompt(&me.name);
                            }
                        }
                    }
                }
            }

            // --- 3. [新增] 监听 Sub 广播消息 ---
            pub_msg = sub.recv() => {
                if let Ok(m) = pub_msg {
                    // [Topic, Payload]
                    if let Some(payload) = m.iter().last() {
                        let json = String::from_utf8_lossy(payload);
                        if let Ok(msg) = serde_json::from_str::<Message>(&json) {
                            if msg.r#type == "CHANNEL_STATE" {
                                println!("\n\n📢 [{}] 收到通道更新广播", me.name);
                                if let Some(list) = msg.commitment {
                                    println!("   状态列表: {}", list);
                                }
                                // 打印完广播后，恢复提示符，以免界面混乱
                                print_prompt(&me.name);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}