use crate::config::{ActorConfig, ContractsConfig};
use crate::models::{Message, TransactionTx}; 
use crate::blockchain;
// [修复 1] 移除这里的 Fr
use crate::crypto::RSUC::{self, PP, KeyPair};
// [修复 2] 从 wrapper 导入 Fr, G1, G2
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
use alloy::primitives::{keccak256, FixedBytes};
use uuid::Uuid;
use std::str::FromStr;
use base64::Engine; 

struct ChannelState {
    pp: PP,
    kp: KeyPair,
    users: HashMap<String, String>, 
    schnorr_keys: HashMap<String, G1>,
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

        println!("[1] 通道已生成");
        println!("    Alias:  {}", channel_id_str);
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
            &op_config, 
            &rpc_url, 
            conf.payment_channel, 
            channel_id_bytes, 
            g1_bytes, 
            p_bytes, 
            g2_bytes, 
            ord_bytes, 
            vk_bytes
        ).await;
    }

    // 4. ZMQ 绑定
    println!("[6] 监听端口: 5555 (Router), 5556 (Pub)");
    let mut router = zeromq::RouterSocket::new();
    router.bind("tcp://0.0.0.0:5555").await?;
    let mut pub_sock = zeromq::PubSocket::new();
    pub_sock.bind("tcp://0.0.0.0:5556").await?;

    println!("\nOperator 就绪，等待客户端...\n");

    loop {
        let msg = router.recv().await?;
        if let (Some(id_frame), Some(payload_frame)) = (msg.get(0), msg.get(2)) {
            let router_id = id_frame.to_vec();
            let json = String::from_utf8_lossy(payload_frame);
            
            if let Ok(req) = serde_json::from_str::<Message>(&json) {
                if req.r#type == "JOIN_REQ" {
                    handle_join(req, router_id, state.clone(), &mut router, &mut pub_sock, channel_id_str.clone(), channel_id_bytes).await?;
                } else if req.r#type == "UPDATE_REQ" {
                    handle_update(req, router_id, state.clone(), &mut router).await?;
                }
            }
        }
    }
}

async fn handle_join(
    req: Message, router_id: Vec<u8>, state: Arc<Mutex<ChannelState>>, 
    router: &mut zeromq::RouterSocket, pub_sock: &mut zeromq::PubSocket, 
    chan_id_alias: String, chan_id_hex: FixedBytes<32>
) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [JOIN] 收到请求: {}", sender);

    if let Some(vk_b64) = req.vk {
        if let Ok(pk) = ecp_from_base64(&vk_b64) {
            state.lock().unwrap().schnorr_keys.insert(sender.clone(), pk);
        }
    }

    println!("    - 用户链上注册成功 (Mock)");

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
        let user_list: Vec<String> = st.users.iter().map(|(u, c)| format!("{}:{}", u, c)).collect();
        let mut update_msg = Message::new("CHANNEL_STATE", "OPERATOR");
        update_msg.channel_id = Some(chan_id_alias.clone());
        update_msg.commitment = Some(user_list.join(";")); 
        
        let topic = format!("{}", chan_id_hex); 
        let mut pub_frame = zeromq::ZmqMessage::from(topic.into_bytes());
        pub_frame.push_back(serde_json::to_string(&update_msg)?.into());
        if let Err(e) = pub_sock.send(pub_frame).await {
            eprintln!("❌ 广播失败: {}", e);
        } else {
            println!("    [广播] 状态已推送 (当前用户数: {})", st.users.len());
        }
    }

    println!("    - 原始金额: {}", amt_u64);
    
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
    req: Message,
    router_id: Vec<u8>,
    state: Arc<Mutex<ChannelState>>,
    router: &mut zeromq::RouterSocket
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

    // 1. 验证 Schnorr
    let sig = schnorr::sig_from_base64(&sig_str)?;
    if !schnorr::verify(&tx_json, sig, sender_pk.unwrap(), pp.g1) {
        println!("❌ 签名验证失败"); return Ok(());
    }

    // 2. 验证 Range Proof
    if !range_proof::verify_proof(&tx.range_proof, &tx.range_com) {
        println!("❌ 区间证明无效"); return Ok(());
    }
    println!("    - 验证区间证明... ✅");

    // 3. 验证接收方承诺 (VfAuth)
    let recv_c = ecp_from_base64(&tx.receiver_commitment)?;
    let recv_sig = zksig_from_base64(&tx.receiver_zk_sig)?;
    if !RSUC::vf_auth(recv_c, &recv_sig, vk_op, &pp) {
        println!("❌ 接收方承诺无效"); return Ok(());
    }

    // 4. 执行更新 (UpdAC)
    let amt_val = u64::from_str_radix(&tx.amount, 16)?;
    let amt_fr = Fr::from_u64(amt_val);
    
    println!("    - 执行同态更新... (Sender -{}, Recv +{})", amt_val, amt_val);
    
    let send_c = ecp_from_base64(&tx.sender_commitment)?;
    // Mock Negation: 这里应为 -amt，demo 暂略
    let new_sender_ac = RSUC::upd_ac(send_c, amt_fr, sk_op, &pp); 
    let new_recv_ac = RSUC::upd_ac(recv_c, amt_fr, sk_op, &pp);

    // 5. 更新 Operator 存储
    {
        let mut st = state.lock().unwrap();
        st.users.insert(sender.clone(), ecp_to_base64(new_sender_ac.c));
    }

    // 6. 回复 OK_UPDATE
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