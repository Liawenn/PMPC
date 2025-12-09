use crate::config::{ActorConfig, ContractsConfig};
use crate::models::{Message, TransactionTx}; 
use crate::blockchain;
use crate::crypto::RSUC::{self, PP, KeyPair}; 
use crate::crypto::RSUC::wrapper::{Fr, G1, G2};
use crate::crypto::RSUC::utils::{
    ecp_to_base64, ecp_from_base64, zksig_to_base64, zksig_from_base64, 
    ecp2_to_base64, hash256, xor_r
};
use crate::crypto::{schnorr, range_proof}; 
use std::error::Error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeromq::{Socket, SocketRecv, SocketSend};
use alloy::primitives::{keccak256, FixedBytes, Address};
use uuid::Uuid;
use std::str::FromStr;
use base64::Engine; 
use tokio::time::{interval, sleep, Duration};

#[derive(PartialEq, Debug)]
enum OpStatus {
    Running,    
    Settling,   
}

// [修改] 增加 ID 字段，使 State 自包含通道信息
pub struct ChannelState {
    pub channel_id_str: String,
    pub channel_id_bytes: FixedBytes<32>,
    pp: PP,
    kp: KeyPair,
    users: HashMap<String, String>, 
    schnorr_keys: HashMap<String, G1>,
    status: OpStatus,
    epoch_round: u64,
    pending_joins: Vec<(Message, Vec<u8>)>, 
}

// ==========================================
// 阶段 0: 资金预存 (Fund Operator)
// ==========================================
pub async fn fund_operator(
    op_config: &ActorConfig, 
    rpc_url: &str, 
    contracts: &ContractsConfig,
    amount_wei: u128
) -> Result<(), Box<dyn Error>> {
    println!("\n==== [Phase 0] 资金预存 (Fund Operator) ====");
    println!("👤 Operator: {}", op_config.name);
    println!("💰 正在向合约充值: {} wei...", amount_wei);
    
    // 仅执行锁仓，不创建通道
    blockchain::lock_deposit(op_config, rpc_url, contracts.payment_channel, amount_wei).await?;
    
    println!("✅ 资金锁定成功！Operator 余额已增加。");
    Ok(())
}

// ==========================================
// 阶段 1: 创建通道 (Create Channel) - 极速
// ==========================================
pub async fn create_channel(
    op_config: &ActorConfig, 
    rpc_url: &str, 
    contracts: &ContractsConfig
) -> Result<(String, FixedBytes<32>), Box<dyn Error>> {
    println!("\n==== [Phase 1] 创建通道 (Create Channel) ====");
    
    // 1. 生成 ID
    let uuid = Uuid::new_v4();
    let channel_id_str = format!("ch-{}", &uuid.to_string()[0..8]);
    let channel_id_bytes = keccak256(channel_id_str.as_bytes());
    
    println!("🆔 拟定 Channel ID: {}", channel_id_str);
    println!("    Hex: {}", channel_id_bytes);

    // 2. 调用合约 createChannel (前提：Phase 0 已执行，合约内有余额)
    println!("🔗 正在链上注册通道...");
    let t = std::time::Instant::now();
    
    // 这里不再调用 lock_deposit，直接利用 Phase 0 充值的余额
    let tx_hash = blockchain::create_channel(
        op_config, 
        rpc_url, 
        contracts.payment_channel, 
        channel_id_bytes
    ).await?;
    
    println!("✅ 通道注册成功! Tx: {}", tx_hash);
    println!("⏱️ create耗时: {:?}", t.elapsed());

    Ok((channel_id_str, channel_id_bytes))
}

// ==========================================
// 阶段 2: 初始化参数 (Init Channel) - 耗时
// ==========================================
// operator.rs

pub async fn init_channel(
    op_config: &ActorConfig,
    rpc_url: &str,
    contracts: &ContractsConfig,
    channel_id_str: String,
    channel_id_bytes: FixedBytes<32>
) -> Result<Arc<Mutex<ChannelState>>, Box<dyn Error>> {
    println!("\n==== [Phase 2] 初始化参数 (Init Channel) ====");
    
    // 1. RSUC 密码学参数生成 (CPU 密集，依然很快)
    println!("⚙️ [Init] 正在生成 RSUC 公共参数 (KeyGen)...");
    let t_calc = std::time::Instant::now();
    let pp = RSUC::setup();
    let kp = RSUC::key_gen(&pp);
    println!("   ✅ 参数生成完毕，耗时: {:?}", t_calc.elapsed());

    // =========================================================
    // [新增] 2. 等待通道在链上确认 (Spinlock)
    // =========================================================
    println!("⏳ [Init] 正在等待链上通道确认 (等待出块)...");
    let mut retries = 0;
    loop {
        // 调用 blockchain.rs 中新增的 check_channel_ready
        let is_ready = blockchain::check_channel_ready(
            rpc_url, 
            contracts.payment_channel, 
            channel_id_bytes
        ).await?;

        if is_ready {
            println!("   ✅ 通道已确认上链！(Retries: {})", retries);
            break;
        }

        retries += 1;
        if retries % 5 == 0 {
            print!("."); // 每5秒打印一个点
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
        
        // 等待 1 秒再查
        sleep(Duration::from_secs(1)).await;
        
        // 可选：设置超时（例如 60秒）
        if retries > 60 {
            return Err("❌ 通道创建超时，请检查 Operator 余额或网络状态".into());
        }
    }
    println!(""); // 换行

    // 3. 准备上传的数据
    let g1_bytes = hex::decode(pp.g1.to_hex())?;
    let p_bytes  = hex::decode(pp.p.to_hex())?;
    let g2_bytes = hex::decode(pp.g2.to_hex())?;
    let vk_bytes = hex::decode(kp.vk.to_hex())?;
    let ord_bytes = vec![]; 

    // 4. 调用合约 setupRSUC (现在肯定能成功了)
    println!("📡 [Init] 正在上传参数到链上 (setupRSUC)...");
    let t_upload = std::time::Instant::now();
    
    // 这里可能会因为网络波动失败，建议也可以加个重试，但通常这里已经稳了
    let tx_hash = blockchain::setup_rsuc(
        op_config, 
        rpc_url, 
        contracts.payment_channel, 
        channel_id_bytes, 
        g1_bytes, p_bytes, g2_bytes, ord_bytes, vk_bytes
    ).await?;
    
    println!("   ✅ 参数上传成功! Tx: {}", tx_hash);
    println!("   ⏱️ 上传耗时: {:?}", t_upload.elapsed());

    // 5. 构建并返回共享状态
    let state = Arc::new(Mutex::new(ChannelState {
        channel_id_str,
        channel_id_bytes,
        pp,
        kp,
        users: HashMap::new(),
        schnorr_keys: HashMap::new(),
        status: OpStatus::Running,
        epoch_round: 1,
        pending_joins: Vec::new(),
    }));

    Ok(state)
}

// ==========================================
// 阶段 3: 运行节点 (Run Node) - 循环
// ==========================================
pub async fn run_node(
    state: Arc<Mutex<ChannelState>>,
    op_config: ActorConfig, 
    rpc_url: String, 
    contracts: Option<ContractsConfig>
) -> Result<(), Box<dyn Error>> {
    println!("\n==== [Phase 3] 启动节点服务 (Run Node) ====");
    
    // 从 State 中提取 ID 信息用于日志和逻辑
    let (chan_id_str, chan_id_bytes) = {
        let st = state.lock().unwrap();
        (st.channel_id_str.clone(), st.channel_id_bytes)
    };
    
    println!("🚀 服务启动 | Channel: {}", chan_id_str);

    // 1. ZMQ 绑定
    println!("📡 监听端口: 5555 (Router), 5556 (Pub)");
    let mut router = zeromq::RouterSocket::new();
    router.bind("tcp://0.0.0.0:5555").await?;
    let mut pub_sock = zeromq::PubSocket::new();
    pub_sock.bind("tcp://0.0.0.0:5556").await?;

    println!("⏳ 等待初始用户加入 (100s)...");
    
    let init_deadline = sleep(Duration::from_secs(100)); 
    tokio::pin!(init_deadline);

    // 2. 初始化窗口循环
    loop {
        tokio::select! {
            _ = &mut init_deadline => {
                println!("⏰ 初始化窗口结束，正式开启 Epoch 1...");
                
                let st = state.lock().unwrap();
                let user_list: Vec<String> = st.users.iter().map(|(u, c)| format!("{}:{}", u, c)).collect();
                let payload = user_list.join(";");
                drop(st); 

                broadcast_msg("CHANNEL_STATE", None, Some(payload), &mut pub_sock, chan_id_bytes).await;
                println!("    [广播] 初始通道状态已推送");

                broadcast_msg("EPOCH_START_SIGNAL", Some(1), None, &mut pub_sock, chan_id_bytes).await;
                break; 
            }
            msg = router.recv() => {
                if let Ok(msg) = msg {
                    process_msg(msg, state.clone(), &mut router, &mut pub_sock, chan_id_str.clone(), chan_id_bytes, true, &op_config, &rpc_url, &contracts).await?;
                }
            }
        }
    }

    // 3. 正式 Epoch 循环
    let mut epoch_timer = interval(Duration::from_secs(100));
    epoch_timer.tick().await; 

    loop {
        tokio::select! {
            _ = epoch_timer.tick() => {
                let mut st = state.lock().unwrap();
                match st.status {
                    OpStatus::Running => {
                        println!("\n⏰ [Timer] Epoch {} 结束，进入结算阶段 (Settling)...", st.epoch_round);
                        st.status = OpStatus::Settling;
                        let round = st.epoch_round;
                        drop(st); 
                        broadcast_msg("EPOCH_END_SIGNAL", Some(round), None, &mut pub_sock, chan_id_bytes).await;
                    },
                    OpStatus::Settling => {
                        let next_round = st.epoch_round + 1;
                        println!("⏰ [Timer] 结算阶段结束，开启 Epoch {} (Running)...", next_round);
                        
                        let pending = std::mem::take(&mut st.pending_joins);
                        drop(st); 

                        if !pending.is_empty() {
                            println!("    ! 恢复处理 {} 个挂起的 Join 请求...", pending.len());
                            for (req, rid) in pending {
                                handle_join(req, rid, state.clone(), &mut router, &mut pub_sock, chan_id_str.clone(), chan_id_bytes, &op_config, &rpc_url, &contracts).await?;
                            }
                        }

                        let mut st = state.lock().unwrap();
                        st.status = OpStatus::Running;
                        st.epoch_round = next_round;
                        
                        let user_list: Vec<String> = st.users.iter().map(|(u, c)| format!("{}:{}", u, c)).collect();
                        let payload = user_list.join(";");
                        drop(st);

                        broadcast_msg("CHANNEL_STATE", None, Some(payload), &mut pub_sock, chan_id_bytes).await;
                        broadcast_msg("EPOCH_START_SIGNAL", Some(next_round), None, &mut pub_sock, chan_id_bytes).await;
                    }
                }
            }

            msg = router.recv() => {
                if let Ok(msg) = msg {
                    process_msg(msg, state.clone(), &mut router, &mut pub_sock, chan_id_str.clone(), chan_id_bytes, false, &op_config, &rpc_url, &contracts).await?;
                }
            }
        }
    }
}

// ==========================================
// 辅助函数 (Helpers)
// ==========================================

async fn broadcast_msg(type_: &str, round: Option<u64>, content: Option<String>, pub_sock: &mut zeromq::PubSocket, topic_bytes: FixedBytes<32>) {
    let mut msg = Message::new(type_, "OPERATOR");
    msg.epoch_round = round;
    msg.commitment = content; 
    let topic = format!("{}", topic_bytes);
    let mut frame = zeromq::ZmqMessage::from(topic.into_bytes()); 
    frame.push_back(serde_json::to_string(&msg).unwrap().into());
    let _ = pub_sock.send(frame).await;
}

async fn process_msg(
    msg: zeromq::ZmqMessage,
    state: Arc<Mutex<ChannelState>>,
    router: &mut zeromq::RouterSocket,
    pub_sock: &mut zeromq::PubSocket,
    chan_id_str: String,
    chan_id_bytes: FixedBytes<32>,
    allow_immediate_join: bool,
    op_config: &ActorConfig,
    rpc_url: &str,
    contracts: &Option<ContractsConfig>
) -> Result<(), Box<dyn Error>> {
    if let (Some(id_frame), Some(payload_frame)) = (msg.get(0), msg.get(2)) {
        let router_id = id_frame.to_vec();
        let json = String::from_utf8_lossy(payload_frame);
        
        if let Ok(req) = serde_json::from_str::<Message>(&json) {
            let is_running = { state.lock().unwrap().status == OpStatus::Running };
            
            match req.r#type.as_str() {
                "JOIN_REQ" => {
                    if allow_immediate_join {
                        handle_join(req, router_id, state.clone(), router, pub_sock, chan_id_str, chan_id_bytes, op_config, rpc_url, contracts).await?;
                    } else {
                        println!(">>> [JOIN] 收到请求 -> 挂起 (等待 Epoch 结束)");
                        state.lock().unwrap().pending_joins.push((req, router_id.clone()));
                        let mut reply = Message::new("WAIT", "OPERATOR");
                        reply.content = Some("请求已挂起，等待 Epoch 结束".into());
                        let mut resp = zeromq::ZmqMessage::from(router_id);
                        resp.push_back(vec![].into());
                        resp.push_back(serde_json::to_string(&reply)?.into());
                        router.send(resp).await?;
                    }
                },
                "UPDATE_REQ" => {
                    if is_running {
                        handle_update(req, router_id, state.clone(), router).await?;
                    } else {
                        println!(">>> [TX] 拒绝 (正在结算)");
                    }
                },
                "EPOCH_REQ" => {
                    if !is_running { 
                        handle_epoch_report(req, router_id, state.clone(), router).await?;
                    }
                },
                "EXIT_REQ" => {
                    handle_exit(req, router_id, state.clone(), router, op_config, rpc_url, contracts, chan_id_bytes).await?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

async fn handle_join(req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, router: &mut zeromq::RouterSocket, _pub_sock: &mut zeromq::PubSocket, chan_id_alias: String, chan_id_hex: FixedBytes<32>, op_config: &ActorConfig, rpc_url: &str, contracts: &Option<ContractsConfig>) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [JOIN] 处理请求: {}", sender);

    if let Some(vk_b64) = req.vk {
        if let Ok(pk) = ecp_from_base64(&vk_b64) {
            state.lock().unwrap().schnorr_keys.insert(sender.clone(), pk);
        }
    }

    if let Some(conf) = contracts {
        if let Some(addr_str) = &req.content {
            if let Ok(user_addr) = Address::from_str(addr_str) {
                println!("    - 正在链上注册用户 {} ...", user_addr);
                
                let mut retry_count = 0;
                let mut result = Err(Box::<dyn Error>::from("Init"));
                
                while retry_count < 3 {
                    result = blockchain::join_channel(op_config, rpc_url, conf.payment_channel, chan_id_hex, user_addr).await;
                    if result.is_ok() {
                        break;
                    }
                    println!("      ⚠️ 链上注册超时或失败，正在重试 ({}/3)...", retry_count + 1);
                    retry_count += 1;
                    sleep(Duration::from_secs(1)).await;
                }

                match result {
                    Ok(_) => println!("    ✅ 链上注册成功 (Tx Confirmed)"),
                    Err(e) => {
                        println!("❌ 链上注册最终失败: {}", e);
                        let mut reply = Message::new("ERROR", "OPERATOR");
                        reply.content = Some(format!("链上注册失败，请稍后重试: {}", e));
                        let mut resp = zeromq::ZmqMessage::from(router_id);
                        resp.push_back(vec![].into());
                        resp.push_back(serde_json::to_string(&reply)?.into());
                        router.send(resp).await?;
                        return Ok(()); 
                    }
                }
            } else {
                println!("❌ 地址格式错误");
                return Ok(());
            }
        } else {
            println!("❌ JOIN 请求缺失以太坊地址，拒绝请求");
            return Ok(());
        }
    }

    println!("    - RSUC状态初始化 (Mock/Real)...");
    let amt_u64 = u64::from_str_radix(&req.amount.unwrap_or("0".into()), 16).unwrap_or(0);
    let v = Fr::from_u64(amt_u64);
    let r = Fr::random(); 
    
    let (ac, vk) = {
        let st = state.lock().unwrap();
        (RSUC::auth_com(v, st.kp.sk, r, &st.pp), st.kp.vk)
    };

    let vk_str = ecp2_to_base64(vk);
    let key = hash256(format!("{}{}", vk_str, sender).as_bytes());
    let cipher_r = xor_r(r, &key);

    {
        let mut st = state.lock().unwrap();
        st.users.insert(sender.clone(), ecp_to_base64(ac.c));
        println!("    - 用户 {} 已加入状态树", sender);
    }
    
    let mut reply = Message::new("OK_JOIN", "OPERATOR");
    reply.channel_id = Some(chan_id_alias);
    reply.amount = Some(format!("{:x}", amt_u64));
    reply.commitment = Some(ecp_to_base64(ac.c));               
    reply.signature = Some(zksig_to_base64(&ac.sigma));         
    reply.cipher_r = Some(base64::engine::general_purpose::STANDARD.encode(cipher_r)); 
    reply.vk = Some(vk_str); 

    let mut resp = zeromq::ZmqMessage::from(router_id);
    resp.push_back(vec![].into()); 
    resp.push_back(serde_json::to_string(&reply)?.into());
    router.send(resp).await?;

    println!("✅ [JOIN] 完成: {} (余额: {})", sender, amt_u64);
    Ok(())
}

async fn handle_update(
    req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, router: &mut zeromq::RouterSocket
) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [TX] 收到隐私交易 (Sender: {})", sender);

    let tx_json = req.tx_data.unwrap();
    let sig_str = req.schnorr_sig.unwrap();
    let tx: TransactionTx = serde_json::from_str(&tx_json)?;

    let (sender_pk, pp, sk_op, vk_op) = {
        let st = state.lock().unwrap();
        (
            st.schnorr_keys.get(&sender).cloned(), 
            st.pp.clone(),
            st.kp.sk,
            st.kp.vk
        )
    };

    if sender_pk.is_none() {
        println!("❌ 发送方未注册"); return Ok(());
    }

    let sig = schnorr::sig_from_base64(&sig_str)?;
    if !schnorr::verify(&tx_json, sig, sender_pk.unwrap(), pp.g1) {
        println!("❌ 签名验证失败"); return Ok(());
    }

    let amt_val = u64::from_str_radix(&tx.amount, 16)?;
    if !range_proof::verify_proof(&tx.range_proof, &tx.sender_commitment, amt_val, &pp) {
        println!("❌ 区间证明无效"); return Ok(());
    }
    println!("    - 验证区间证明... ✅");

    let recv_c = ecp_from_base64(&tx.receiver_commitment)?;
    let recv_sig = zksig_from_base64(&tx.receiver_zk_sig)?;
    if !RSUC::vf_auth(recv_c, &recv_sig, vk_op, &pp) {
        println!("❌ 接收方承诺无效"); return Ok(());
    }

    let amt_fr = Fr::from_u64(amt_val);
    
    println!("    - 执行同态更新... (Sender -{}, Recv +{})", amt_val, amt_val);
    
    let send_c = ecp_from_base64(&tx.sender_commitment)?;
    let new_sender_ac = RSUC::upd_ac(send_c, Fr::zero() - amt_fr, sk_op, &pp);
    let new_recv_ac = RSUC::upd_ac(recv_c, amt_fr, sk_op, &pp);

    {
        let mut st = state.lock().unwrap();
        st.users.insert(sender.clone(), ecp_to_base64(new_sender_ac.c));
    }

    let mut reply = Message::new("OK_UPDATE", "OPERATOR");
    reply.request_id = req.request_id; 

    reply.amount = Some(tx.amount);
    reply.sender_commitment = Some(ecp_to_base64(new_sender_ac.c));
    reply.sender_zk_sig = Some(zksig_to_base64(&new_sender_ac.sigma));
    reply.receiver_commitment = Some(ecp_to_base64(new_recv_ac.c));
    reply.receiver_zk_sig = Some(zksig_to_base64(&new_recv_ac.sigma));

    let mut resp = zeromq::ZmqMessage::from(router_id);
    resp.push_back(vec![].into());
    resp.push_back(serde_json::to_string(&reply)?.into());
    router.send(resp).await?;

    println!("✅ [TX] 成功处理");
    Ok(())
}

async fn handle_epoch_report(
    req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, router: &mut zeromq::RouterSocket
) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [EPOCH] 收到用户 {} 的汇报", sender);

    // 1. 准备回复消息，回显 Request ID
    let mut reply = Message::new("EPOCH_ACK", "OPERATOR");
    reply.request_id = req.request_id; 

    // 2. 获取 Operator 当前视角的用户状态 (可能是发送后的状态)
    let (vk, pp, sk, current_c_str) = {
        let st = state.lock().unwrap();
        (st.kp.vk, st.pp.clone(), st.kp.sk, st.users.get(&sender).cloned())
    };

    if current_c_str.is_none() {
        println!("    ❌ 用户状态丢失或未加入");
        return Ok(());
    }
    // 这是 Sender Current C (C_curr)
    let sender_current_c = ecp_from_base64(&current_c_str.unwrap())?;

    if let Some(updates) = req.epoch_updates {
        if !updates.is_empty() {
            println!("    - 包含 {} 笔交易，正在批量验证...", updates.len());
            
            // [关键修改] 3. 解析 base_commitment
            let base_c_str = &updates[0].base_commitment;
            let epoch_base_c = match ecp_from_base64(base_c_str) {
                Ok(c) => c,
                Err(_) => {
                    println!("    ❌ Base Commitment 解析失败 (可能旧版本客户端)");
                    return Ok(());
                }
            };

            // 4. 解析更新列表
            let mut parsed_updates = Vec::new();
            let mut format_ok = true;
            for item in updates {
                if let (Ok(c), Ok(sig)) = (ecp_from_base64(&item.commitment), zksig_from_base64(&item.signature)) {
                    parsed_updates.push((c, sig));
                } else {
                    println!("    ❌ 汇报数据格式错误 (Base64解析失败)");
                    format_ok = false;
                    break;
                }
            }

            if format_ok {
                // 5. [核心] 调用 RSUC::batch_verify_update
                let result_ac = RSUC::batch_verify_update(
                    sender_current_c, 
                    epoch_base_c, 
                    parsed_updates,
                    sk, vk, &pp
                );

                if let Some(new_ac) = result_ac {
                    // (A) 更新 Operator 内存
                    state.lock().unwrap().users.insert(sender.clone(), ecp_to_base64(new_ac.c));
                    println!("    ✅ 批量验证成功，状态已更新 (New Sig Generated)");

                    // (B) 将新承诺和签名填入回复
                    reply.commitment = Some(ecp_to_base64(new_ac.c));
                    reply.signature = Some(zksig_to_base64(&new_ac.sigma));
                } else {
                    println!("    ❌ 批量验证失败: 签名无效或数学校验不通过");
                }
            }
        } else {
            // updates 为空，说明本轮无接收，无需处理
            println!("    - 无更新 (Empty)");
        }
    }

    let mut resp = zeromq::ZmqMessage::from(router_id);
    resp.push_back(vec![].into());
    resp.push_back(serde_json::to_string(&reply)?.into());
    router.send(resp).await?;

    Ok(())
}

async fn handle_exit(
    req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, router: &mut zeromq::RouterSocket,
    op_config: &ActorConfig, rpc_url: &str, contracts: &Option<ContractsConfig>, chan_id: FixedBytes<32>
) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [EXIT] 收到用户 {} 的退出申请", sender);

    let (stored_c_str, sender_pk, pp) = {
        let st = state.lock().unwrap();
        (st.users.get(&sender).cloned(), st.schnorr_keys.get(&sender).cloned(), st.pp.clone())
    };

    if stored_c_str.is_none() || sender_pk.is_none() {
        println!("❌ 用户不存在或未激活"); return Ok(());
    }
    let stored_c = ecp_from_base64(&stored_c_str.unwrap())?;
    let pk = sender_pk.unwrap();

    let amount_hex = req.amount.as_ref().unwrap();
    let r_val_str = req.r_reveal.as_ref().or(req.cipher_r.as_ref()).unwrap();
    let sig_str = req.schnorr_sig.as_ref().unwrap();
    
    let sig = schnorr::sig_from_base64(sig_str)?;
    let payload = format!("EXIT{}{}", amount_hex, r_val_str);
    
    if !schnorr::verify(&payload, sig, pk, pp.g1) {
        println!("❌ 退出签名验证失败"); return Ok(());
    }

    let v_val = u64::from_str_radix(amount_hex, 16)?;
    let v = Fr::from_u64(v_val);
    let r = Fr::from_hex(r_val_str)?;
    let calc_c = (pp.g1 * v) + (pp.p * r);
    
    if ecp_to_base64(calc_c) != ecp_to_base64(stored_c) {
        println!("❌ 余额欺诈！(承诺不匹配)");
        return Ok(());
    }
    println!("    - 验证通过：余额真实有效 ({})", v_val);

    let mut withdraw_success = true;

    if let Some(conf) = contracts {
        if let Some(addr_str) = &req.content {
            if let Ok(user_addr) = Address::from_str(addr_str.trim()) {
                println!("    - 正在执行链上提现 (To: {})...", user_addr);
                match blockchain::operator_withdraw(op_config, rpc_url, conf.payment_channel, chan_id, user_addr, v_val as u128).await {
                    Ok(tx) => println!("✅ 链上提现成功 Tx: {}", tx),
                    Err(e) => {
                        println!("❌ 链上提现失败: {}", e);
                        withdraw_success = false;
                    }
                }
            } else {
                println!("❌ 地址解析失败"); 
                return Ok(());
            }
        }
    }

    if withdraw_success {
        let reply = Message::new("EXIT_ACK", "OPERATOR");
        let mut resp = zeromq::ZmqMessage::from(router_id);
        resp.push_back(vec![].into());
        resp.push_back(serde_json::to_string(&reply)?.into());
        router.send(resp).await?;

        let remaining_count = {
            let mut st = state.lock().unwrap();
            st.users.remove(&sender);
            st.users.len()
        };
        
        println!("✅ 用户 {} 已安全退出。剩余用户: {}", sender, remaining_count);

        if remaining_count == 0 {
            if let Some(conf) = contracts {
                println!("⏳ 通道已空闲。启动 100s 倒计时，若无新用户加入将关闭通道...");

                let state_clone = state.clone();
                let op_config_clone = op_config.clone();
                let rpc_url_clone = rpc_url.to_string();
                let contract_addr = conf.payment_channel;
                let chan_id_clone = chan_id;

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(100)).await;

                    let current_count = {
                        state_clone.lock().unwrap().users.len()
                    };

                    if current_count > 0 {
                        println!("✋ [Auto-Close] 倒计时结束，但在窗口期内有 {} 位新用户加入。取消关闭。", current_count);
                    } else {
                        println!("🔒 [Auto-Close] 倒计时结束，通道仍为空。正在执行链上关闭...");
                        
                        let t = std::time::Instant::now();
                        match blockchain::close_channel(
                            &op_config_clone, 
                            &rpc_url_clone, 
                            contract_addr, 
                            chan_id_clone
                        ).await {
                            Ok(tx) => {
                                println!("🎉 [Auto-Close] 通道关闭成功！Tx: {}", tx);
                                println!("💰 保证金已赎回。Operator 服务停止。");
                                std::process::exit(0);
                            },
                            Err(e) => {
                                println!("❌ [Auto-Close] 关闭失败: {}", e);
                            }
                        }
                        println!("⏱️ close耗时: {:?}", t.elapsed());
                    }
                });
            }
        }

    } else {
        let mut reply = Message::new("WAIT", "OPERATOR");
        reply.content = Some("链上提现执行失败，请联系 Operator 或稍后重试".into());
        let mut resp = zeromq::ZmqMessage::from(router_id);
        resp.push_back(vec![].into());
        resp.push_back(serde_json::to_string(&reply)?.into());
        router.send(resp).await?;
        println!("⚠️ 链上操作失败，保留用户 {} 状态以供重试", sender);
    }
    
    Ok(())
}