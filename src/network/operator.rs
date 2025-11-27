use crate::config::{ActorConfig, ContractsConfig};
use crate::models::Message;
use crate::blockchain;
use crate::crypto::RSUC::{self, PP, KeyPair};
use crate::crypto::RSUC::wrapper::Fr; 
use crate::crypto::RSUC::utils::{ecp_to_base64, zksig_to_base64, ecp2_to_base64, hash256, xor_r};
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
    }));

    // 3. 上传参数
    if let Some(conf) = &contracts {
        println!("[5] 上传参数到合约...");
        let _ = blockchain::setup_rsuc(&op_config, &rpc_url, conf.payment_channel, channel_id_bytes, 
            vec![], vec![], vec![], vec![], vec![]).await;
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
                    handle_join(
                        req, 
                        router_id, 
                        state.clone(), 
                        &mut router, 
                        &mut pub_sock, 
                        channel_id_str.clone(), 
                        channel_id_bytes
                    ).await?;
                }
            }
        }
    }
}

async fn handle_join(
    req: Message,
    router_id: Vec<u8>,
    state: Arc<Mutex<ChannelState>>,
    router: &mut zeromq::RouterSocket,
    pub_sock: &mut zeromq::PubSocket,
    chan_id_alias: String,
    chan_id_hex: FixedBytes<32>
) -> Result<(), Box<dyn Error>> {
    let sender = req.sender.clone();
    println!(">>> [JOIN] 收到请求: {}", sender);

    println!("    - 用户链上注册成功 (Mock)");

    // RSUC 计算
    let amt_u64 = u64::from_str_radix(&req.amount.unwrap_or("0".into()), 16).unwrap_or(0);
    let v = Fr::from_u64(amt_u64);
    let r = Fr::random(); 
    
    let (ac, vk) = {
        let st = state.lock().unwrap();
        let commitment = RSUC::auth_com(v, st.kp.sk, r, &st.pp);
        (commitment, st.kp.vk)
    };

    // 加密随机数 r (使用 VK 作为 Key 种子)
    let vk_str = ecp2_to_base64(vk);
    let key = hash256(format!("{}{}", vk_str, sender).as_bytes());
    let cipher_r = xor_r(r, &key);

    // 更新状态并广播
    {
        let mut st = state.lock().unwrap();
        st.users.insert(sender.clone(), ecp_to_base64(ac.c));

        let mut broadcast_payload = String::new();
        let user_list: Vec<String> = st.users.iter()
            .map(|(u, c)| format!("{}:{}", u, c))
            .collect();
        broadcast_payload = user_list.join(";");

        let mut update_msg = Message::new("CHANNEL_STATE", "OPERATOR");
        update_msg.channel_id = Some(chan_id_alias.clone());
        update_msg.commitment = Some(broadcast_payload); 
        
        let topic = format!("{}", chan_id_hex); 
        let mut pub_frame = zeromq::ZmqMessage::from(topic.into_bytes());
        pub_frame.push_back(serde_json::to_string(&update_msg)?.into());
        if let Err(e) = pub_sock.send(pub_frame).await {
            eprintln!("❌ 广播失败: {}", e);
        } else {
            println!("    [广播] 状态已推送 (当前用户数: {})", st.users.len());
        }
    }

    // 回复 OK_JOIN
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
    
    if let Err(e) = router.send(resp).await {
        eprintln!("❌ 回复失败: {}", e);
    } else {
        println!("✅ [JOIN] 完成: {} (余额: {})", sender, amt_u64);
    }
    
    Ok(())
}