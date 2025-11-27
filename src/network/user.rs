use crate::config::{ActorConfig, ContractsConfig};
use crate::models::Message;
use crate::wallet::UserWallet;
use crate::blockchain;
use crate::crypto::RSUC::{self, PP}; 
use crate::crypto::RSUC::wrapper::{Fr, G1, G2};
use crate::crypto::RSUC::utils::{
    ecp_from_base64, zksig_from_base64, ecp2_to_base64, 
    ecp_to_base64, hash256, recover_r_from_bytes
};
use std::error::Error;
use zeromq::{Socket, SocketSend, SocketRecv};
use tokio::io::{AsyncBufReadExt, BufReader};
use std::sync::{Arc, Mutex};
use alloy::primitives::FixedBytes;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

pub async fn run(
    me: ActorConfig, 
    op: ActorConfig, 
    rpc_url: String, 
    contracts: Option<ContractsConfig>,
    initial_deposit: Option<u128>
) -> Result<(), Box<dyn Error>> {
    println!("\n=== USER 启动 ===");
    println!("👤 身份: {}", me.name);

    if let Some(conf) = &contracts {
        if let Some(amt) = initial_deposit {
             let _ = blockchain::lock_deposit(&me, &rpc_url, conf.payment_channel, amt).await;
        }
    }

    let wallet = Arc::new(Mutex::new(UserWallet::new(initial_deposit.unwrap_or(0))));

    let mut dealer = zeromq::DealerSocket::new();
    let op_host = op.host.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let op_port = op.port.unwrap_or(5555);
    let op_addr = format!("tcp://{}:{}", op_host, op_port);
    
    dealer.connect(&op_addr).await?;
    println!("🔄 已连接 Operator: {}", op_addr);

    let mut pp: Option<PP> = None;
    // [新增] 缓存从链上获取的 Operator VK
    let mut cached_op_vk: Option<G2> = None; 

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    println!("\n{} 准备就绪. 输入 'join <hex_id>' 加入通道", me.name);

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                if let Ok(Some(cmd_str)) = line {
                    let parts: Vec<&str> = cmd_str.trim().split_whitespace().collect();
                    if parts.is_empty() { continue; }

                    match parts[0] {
                        "join" => {
                            if parts.len() < 2 { println!("❌ 用法: join <hex_id>"); continue; }
                            let ch_id_str = parts[1];
                            
                            if let Some(conf) = &contracts {
                                if let Ok(ch_id_bytes) = FixedBytes::<32>::from_str(ch_id_str) {
                                    println!("⏳ 正在从链上获取 RSUC 参数...");
                                    match blockchain::get_rsuc_info(&rpc_url, conf.payment_channel, ch_id_bytes).await {
                                        Ok((g1_b, p_b, g2_b, _, vk_b)) => {
                                            let g1 = G1::from_hex(&hex::encode(g1_b)).unwrap_or(G1::generator());
                                            let p  = G1::from_hex(&hex::encode(p_b)).unwrap_or(G1::generator());
                                            let g2 = G2::from_hex(&hex::encode(g2_b)).unwrap_or(G2::generator());
                                            
                                            // [新增] 解析并缓存 VK
                                            let vk = G2::from_hex(&hex::encode(vk_b)).unwrap_or(G2::generator());
                                            cached_op_vk = Some(vk);

                                            pp = Some(PP { g1, p, g2 });
                                            println!("[INFO] RSUC 参数加载成功");
                                        },
                                        Err(e) => {
                                            println!("❌ 获取参数失败: {} (Mock Mode)", e);
                                            pp = Some(RSUC::setup());
                                            // Mock VK
                                            cached_op_vk = Some(G2::generator()); 
                                        }
                                    }
                                }
                            } else {
                                pp = Some(RSUC::setup());
                                cached_op_vk = Some(G2::generator());
                            }

                            let temp_pp = pp.as_ref().unwrap();
                            let user_sk = Fr::random(); 
                            let user_pk = temp_pp.g1 * user_sk; 
                            
                            let cur_amt = wallet.lock().unwrap().amount;
                            let mut req = Message::new("JOIN_REQ", &me.name);
                            req.channel_id = Some(ch_id_str.to_string());
                            req.amount = Some(format!("{:x}", cur_amt)); 
                            req.vk = Some(ecp_to_base64(user_pk)); 

                            let mut zmq_msg = zeromq::ZmqMessage::from(vec![]); 
                            zmq_msg.push_back(serde_json::to_string(&req)?.into()); 
                            dealer.send(zmq_msg).await?;
                            
                            println!("[INFO] JOIN 发送中 (带 Schnorr 公钥)...");
                        },
                        "exit" => break,
                        _ => println!("❌ 未知命令"),
                    }
                }
            }

            msg = dealer.recv() => {
                if let Ok(m) = msg {
                    if let Some(payload) = m.iter().last() {
                        let json = String::from_utf8_lossy(payload);
                        if let Ok(resp) = serde_json::from_str::<Message>(&json) {
                            
                            if resp.r#type == "OK_JOIN" {
                                println!("\n[INFO] [Dealer] 收到 Operator 的加入确认 (OK_JOIN)");
                                
                                if resp.commitment.is_none() || resp.signature.is_none() || resp.cipher_r.is_none() {
                                    println!("❌ 错误: OK_JOIN 数据缺失");
                                    continue;
                                }

                                if pp.is_none() || cached_op_vk.is_none() {
                                    println!("❌ 错误: 本地 PP/VK 未初始化，请先执行 join");
                                    continue;
                                }
                                let local_pp = pp.as_ref().unwrap();
                                // [关键修改] 使用缓存的 Chain VK
                                let chain_vk = cached_op_vk.unwrap(); 

                                let c = ecp_from_base64(&resp.commitment.unwrap())?;
                                let sigma = zksig_from_base64(&resp.signature.unwrap())?;
                                let cipher_bytes = general_purpose::STANDARD.decode(resp.cipher_r.unwrap())?;
                                let amt_val = u64::from_str_radix(&resp.amount.unwrap_or("0".into()), 16)?;

                                // [关键修改] 密钥生成：Hash(ChainVK_Base64 + UserName)
                                // 确保 Operator 那边也是用 Base64 格式的 VK 生成 Key
                                let vk_base64 = ecp2_to_base64(chain_vk);
                                let key_material = format!("{}{}", vk_base64, me.name);
                                let key = hash256(key_material.as_bytes());
                                
                                // 解密 r
                                let mut r_bytes = vec![0u8; cipher_bytes.len()];
                                for i in 0..cipher_bytes.len() {
                                    r_bytes[i] = cipher_bytes[i] ^ key[i % key.len()];
                                }
                                // 使用修复后的 recover (32字节)
                                let r = recover_r_from_bytes(&r_bytes);
                                
                                // 验证
                                let v_fr = Fr::from_u64(amt_val);
                                let ok_com = RSUC::vf_com(c, v_fr, r, local_pp);
                                let ok_auth = RSUC::vf_auth(c, &sigma, chain_vk, local_pp);
                                
                                if ok_com && ok_auth {
                                    let ac = RSUC::AuthCommitment { c, sigma };
                                    wallet.lock().unwrap().init_from_operator(ac, r, local_pp);
                                    println!("[SUCCESS] 加入成功！钱包初始化完成 | 余额: {} wei", amt_val);
                                } else {
                                    println!("❌ [ERROR] 验证失败: Com={}, Auth={}", ok_com, ok_auth);
                                }
                            }
                            else if resp.r#type == "CHANNEL_STATE" {
                                println!("📢 [{}] 收到通道更新广播: {}", me.name, resp.commitment.unwrap_or("".into()));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}