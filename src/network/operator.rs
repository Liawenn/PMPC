use crate::config::{ActorConfig, ContractsConfig};
use crate::models::{Message, TransactionTx, EpochUpdateItem}; 
use crate::blockchain;
use crate::crypto::RSUC::{self, PP, KeyPair, batch_verify_update}; 
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

struct ChannelState {
    pp: PP,
    kp: KeyPair,
    users: HashMap<String, String>, 
    schnorr_keys: HashMap<String, G1>,
    status: OpStatus,
    epoch_round: u64,
    pending_joins: Vec<(Message, Vec<u8>)>, 
}

pub async fn run(
    op_config: ActorConfig, 
    rpc_url: String, 
    contracts: Option<ContractsConfig>,
    initial_deposit: Option<u128>
) -> Result<(), Box<dyn Error>> {
    println!("\n==== OPERATOR 启动序列 ====");
    println!("👤 身份: {}", op_config.name);

    let mut channel_id_str = String::new();
    let mut channel_id_bytes = FixedBytes::<32>::ZERO;

    // 1. 链上操作
    if let Some(conf) = &contracts {
        let amount = initial_deposit.unwrap_or(20);
        println!("[2] 正在锁仓 {} wei...", amount);
        let _ = blockchain::lock_deposit(&op_config, &rpc_url, conf.payment_channel, amount).await;

        let uuid = Uuid::new_v4();
        channel_id_str = format!("ch-{}", &uuid.to_string()[0..8]);
        channel_id_bytes = keccak256(channel_id_str.as_bytes());

        println!("[1] 通道已生成: {}", channel_id_str);
        println!("    Hex ID: {}", channel_id_bytes);

        println!("[3] 正在链上注册通道...");
        let _ = blockchain::create_channel(&op_config, &rpc_url, conf.payment_channel, channel_id_bytes).await;
    }

    // 2. RSUC 初始化
    println!("[4] 初始化 RSUC 参数...");
    let pp = RSUC::setup();
    let kp = RSUC::key_gen(&pp);
    
    let state = Arc::new(Mutex::new(ChannelState {
        pp: pp.clone(),
        kp: kp.clone(),
        users: HashMap::new(),
        schnorr_keys: HashMap::new(),
        status: OpStatus::Running,
        epoch_round: 1,
        pending_joins: Vec::new(),
    }));

    // 3. 上传参数
    if let Some(conf) = &contracts {
        println!("[5] 上传参数到合约...");
        let g1_bytes = hex::decode(pp.g1.to_hex())?;
        let p_bytes  = hex::decode(pp.p.to_hex())?;
        let g2_bytes = hex::decode(pp.g2.to_hex())?;
        let vk_bytes = hex::decode(kp.vk.to_hex())?;
        let ord_bytes = vec![]; 

        println!("    >>> [Debug] Uploading G1: {}...", &hex::encode(&g1_bytes)[0..10]);
        let _ = blockchain::setup_rsuc(
            &op_config, &rpc_url, conf.payment_channel, channel_id_bytes, 
            g1_bytes, p_bytes, g2_bytes, ord_bytes, vk_bytes
        ).await;
    }

    // 4. ZMQ 绑定
    println!("[6] 监听端口: 5555 (Router), 5556 (Pub)");
    let mut router = zeromq::RouterSocket::new();
    router.bind("tcp://0.0.0.0:5555").await?;
    let mut pub_sock = zeromq::PubSocket::new();
    pub_sock.bind("tcp://0.0.0.0:5556").await?;

    println!("\nOperator 就绪. 等待初始用户加入 (60s)...");
    
    let init_deadline = sleep(Duration::from_secs(60));
    tokio::pin!(init_deadline);

    loop {
        tokio::select! {
            _ = &mut init_deadline => {
                println!("⏰ 初始化窗口结束，正式开启 Epoch 1 (60s)...");
                
                let st = state.lock().unwrap();
                let user_list: Vec<String> = st.users.iter().map(|(u, c)| format!("{}:{}", u, c)).collect();
                let payload = user_list.join(";");
                drop(st); 

                broadcast_msg("CHANNEL_STATE", None, Some(payload), &mut pub_sock, channel_id_bytes).await;
                println!("    [广播] 初始通道状态已推送");

                broadcast_msg("EPOCH_START_SIGNAL", Some(1), None, &mut pub_sock, channel_id_bytes).await;
                
                break; 
            }
            msg = router.recv() => {
                if let Ok(msg) = msg {
                    process_msg(msg, state.clone(), &mut router, &mut pub_sock, channel_id_str.clone(), channel_id_bytes, true, &op_config, &rpc_url, &contracts).await?;
                }
            }
        }
    }

    let mut epoch_timer = interval(Duration::from_secs(60));
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
                        broadcast_msg("EPOCH_END_SIGNAL", Some(round), None, &mut pub_sock, channel_id_bytes).await;
                    },
                    OpStatus::Settling => {
                        let next_round = st.epoch_round + 1;
                        println!("⏰ [Timer] 结算阶段结束，开启 Epoch {} (Running)...", next_round);
                        
                        let pending = std::mem::take(&mut st.pending_joins);
                        drop(st); 

                        if !pending.is_empty() {
                            println!("    ! 恢复处理 {} 个挂起的 Join 请求...", pending.len());
                            for (req, rid) in pending {
                                handle_join(req, rid, state.clone(), &mut router, &mut pub_sock, channel_id_str.clone(), channel_id_bytes, &op_config, &rpc_url, &contracts).await?;
                            }
                        }

                        let mut st = state.lock().unwrap();
                        st.status = OpStatus::Running;
                        st.epoch_round = next_round;
                        
                        let user_list: Vec<String> = st.users.iter().map(|(u, c)| format!("{}:{}", u, c)).collect();
                        let payload = user_list.join(";");
                        drop(st);

                        broadcast_msg("CHANNEL_STATE", None, Some(payload), &mut pub_sock, channel_id_bytes).await;
                        broadcast_msg("EPOCH_START_SIGNAL", Some(next_round), None, &mut pub_sock, channel_id_bytes).await;
                    }
                }
            }

            msg = router.recv() => {
                if let Ok(msg) = msg {
                    process_msg(msg, state.clone(), &mut router, &mut pub_sock, channel_id_str.clone(), channel_id_bytes, false, &op_config, &rpc_url, &contracts).await?;
                }
            }
        }
    }
}

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

async fn handle_join(req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, router: &mut zeromq::RouterSocket, pub_sock: &mut zeromq::PubSocket, chan_id_alias: String, chan_id_hex: FixedBytes<32>, op_config: &ActorConfig, rpc_url: &str, contracts: &Option<ContractsConfig>) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [JOIN] 处理请求: {}", sender);

    if let Some(vk_b64) = req.vk {
        if let Ok(pk) = ecp_from_base64(&vk_b64) {
            state.lock().unwrap().schnorr_keys.insert(sender.clone(), pk);
        }
    }

    // [关键修改] 链上注册逻辑加强
    if let Some(conf) = contracts {
        if let Some(addr_str) = &req.content {
            if let Ok(user_addr) = Address::from_str(addr_str) {
                println!("    - 正在链上注册用户 {} ...", user_addr);
                
                // [修改] 使用 `?` 传播错误。如果链上失败，函数在这里中止，不会执行后面的逻辑。
                match blockchain::join_channel(op_config, rpc_url, conf.payment_channel, chan_id_hex, user_addr).await {
                    Ok(_) => println!("    ✅ 链上注册成功 (Tx Confirmed)"),
                    Err(e) => {
                        println!("❌ 链上注册失败: {}", e);
                        // 返回错误，阻止用户加入状态树
                        let mut reply = Message::new("ERROR", "OPERATOR");
                        reply.content = Some(format!("链上注册失败: {}", e));
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
            // [修改] 如果没有提供 content (地址)，直接报错，防止假注册
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

    // [关键修复] 传入 4 个参数验证区间证明
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
    let new_sender_ac = RSUC::upd_ac(send_c, Fr::zero() - amt_fr, sk_op, &pp); // 扣款 (使用减法或加负数)
    let new_recv_ac = RSUC::upd_ac(recv_c, amt_fr, sk_op, &pp);

    {
        let mut st = state.lock().unwrap();
        st.users.insert(sender.clone(), ecp_to_base64(new_sender_ac.c));
    }

    let mut reply = Message::new("OK_UPDATE", "OPERATOR");
    reply.amount = Some(tx.amount);
    reply.sender_commitment = Some(ecp_to_base64(new_sender_ac.c));
    reply.sender_zk_sig = Some(zksig_to_base64(&new_sender_ac.sigma));
    reply.receiver_commitment = Some(ecp_to_base64(new_recv_ac.c));
    reply.receiver_zk_sig = Some(zksig_to_base64(&new_recv_ac.sigma));
    reply.content = req.content; 

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

    if let Some(updates) = req.epoch_updates {
        if !updates.is_empty() {
            println!("    - 包含 {} 笔交易，正在聚合...", updates.len());
            let (sk, vk, pp, base_c_str) = {
                let st = state.lock().unwrap();
                let base = st.users.get(&sender).unwrap().clone(); 
                (st.kp.sk, st.kp.vk, st.pp.clone(), base)
            };
            
            let base_c = ecp_from_base64(&base_c_str)?;
            
            // [修复] 构建 Vec<(G1, ZKSig)> 列表
            let mut updates_list = Vec::new();
            for item in updates {
                if let (Ok(c), Ok(sig)) = (ecp_from_base64(&item.commitment), zksig_from_base64(&item.signature)) {
                    updates_list.push((c, sig));
                }
            }

            // [修复] 传入 6 个参数
            if let Some(new_ac) = batch_verify_update(base_c, base_c, updates_list, sk, vk, &pp) {
                state.lock().unwrap().users.insert(sender.clone(), ecp_to_base64(new_ac.c));
                println!("    - 用户状态已聚合更新 (New C) ✅");
            } else {
                println!("    ❌ 批量更新验证失败");
            }
        } else {
            println!("    - 无更新 (Empty)");
        }
    }

    let reply = Message::new("EPOCH_ACK", "OPERATOR");
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

    // 1. 验证 Schnorr
    let amount_hex = req.amount.as_ref().unwrap();
    let r_val_str = req.r_reveal.as_ref().or(req.cipher_r.as_ref()).unwrap();
    let sig_str = req.schnorr_sig.as_ref().unwrap();
    
    let sig = schnorr::sig_from_base64(sig_str)?;
    let payload = format!("EXIT{}{}", amount_hex, r_val_str);
    
    if !schnorr::verify(&payload, sig, pk, pp.g1) {
        println!("❌ 退出签名验证失败"); return Ok(());
    }

    // 2. 验证承诺一致性
    let v_val = u64::from_str_radix(amount_hex, 16)?;
    let v = Fr::from_u64(v_val);
    let r = Fr::from_hex(r_val_str)?;
    let calc_c = (pp.g1 * v) + (pp.p * r);
    
    if ecp_to_base64(calc_c) != ecp_to_base64(stored_c) {
        println!("❌ 余额欺诈！(承诺不匹配)");
        return Ok(());
    }
    println!("    - 验证通过：余额真实有效 ({})", v_val);

    // 3. 链上提现
    // [重要修改] 使用 withdraw_success 追踪链上状态
    let mut withdraw_success = true;

    if let Some(conf) = contracts {
        if let Some(addr_str) = &req.content {
            if let Ok(user_addr) = Address::from_str(addr_str.trim()) {
                println!("    - 正在执行链上提现 (To: {})...", user_addr);
                match blockchain::operator_withdraw(op_config, rpc_url, conf.payment_channel, chan_id, user_addr, v_val as u128).await {
                    Ok(tx) => println!("✅ 链上提现成功 Tx: {}", tx),
                    Err(e) => {
                        println!("❌ 链上提现失败: {}", e);
                        withdraw_success = false; // 标记失败
                    }
                }
            } else {
                println!("❌ 地址解析失败"); 
                return Ok(());
            }
        }
    }

    // 4. 根据结果决定是否移除用户
    if withdraw_success {
        // 成功：回复 ACK 并移除状态
        let reply = Message::new("EXIT_ACK", "OPERATOR");
        let mut resp = zeromq::ZmqMessage::from(router_id);
        resp.push_back(vec![].into());
        resp.push_back(serde_json::to_string(&reply)?.into());
        router.send(resp).await?;

        state.lock().unwrap().users.remove(&sender);
        println!("✅ 用户 {} 已安全退出", sender);
    } else {
        // 失败：通知用户，不移除状态
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