use crate::crypto::RSUC::{self, AuthCommitment, PP, rdm_ac, upd_ac, unrandomize}; // [新增] unrandomize
use crate::crypto::RSUC::wrapper::{Fr, G1, G2};
use crate::crypto::RSUC::utils::{ecp_to_base64, zksig_to_base64};
use crate::models::EpochUpdateItem;
use alloy::primitives::U256;
use std::convert::TryInto;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct WalletBaseState {
    pub ac: AuthCommitment,
    pub r: Fr,
}

#[derive(Clone, Debug)]
pub struct WalletReceptionState {
    pub ac: AuthCommitment,
    pub r: Fr,
    pub r_delta: Fr, 
}

impl WalletReceptionState {
    pub fn from_base(base: &WalletBaseState, pp: &PP) -> (Self, Fr) {
        let r_delta = Fr::random(); 
        let new_ac = rdm_ac(base.ac.c, &base.ac.sigma, r_delta, pp);
        (Self { ac: new_ac, r: base.r, r_delta }, r_delta)
    }

    pub fn rerandomize(&self, pp: &PP) -> (Self, Fr) {
        let r_delta = Fr::random();
        let new_ac = rdm_ac(self.ac.c, &self.ac.sigma, r_delta, pp);
        (Self { ac: new_ac, r: self.r, r_delta }, r_delta)
    }
}

#[derive(Clone, Debug)]
pub struct UserWallet {
    pub amount: U256,         // 已结算的主余额
    pub pending_amount: U256, // 扣除发送后的临时余额 (amount - spent)
    
    // [修复] 新增字段：本轮累计接收收入 (received)
    pub current_epoch_income: U256, 
    // [修复] 新增字段：Epoch 暂存区
    pub epoch_buffer: Vec<EpochUpdateItem>,

    pub base: Option<WalletBaseState>,
    pub reception: Option<WalletReceptionState>,
    pub schnorr_sk: Option<Fr>,
    pub schnorr_pk: Option<G1>,
    pub peer_receptions: HashMap<String, AuthCommitment>,
}

impl UserWallet {
    pub fn new(amount: u128) -> Self {
        let amt = U256::from(amount);
        Self {
            amount: amt,
            pending_amount: amt,
            current_epoch_income: U256::ZERO, // [修复] 初始化
            epoch_buffer: Vec::new(),         // [修复] 初始化
            base: None,
            reception: None,
            schnorr_sk: None,
            schnorr_pk: None,
            peer_receptions: HashMap::new(),
        }
    }

    pub fn gen_schnorr_keys(&mut self, pp: &PP) -> G1 {
        let sk = Fr::random();
        let pk = pp.g1 * sk;
        self.schnorr_sk = Some(sk);
        self.schnorr_pk = Some(pk);
        pk
    }

    pub fn init_from_operator(&mut self, ac: AuthCommitment, r: Fr, _pp: &PP) {
        println!("  [Wallet] 正在初始化本地钱包状态...");
        let base = WalletBaseState { ac, r };
        // 初始不生成 reception，等 share_addr 再生成
        self.base = Some(base);
        self.reception = None; 
        println!("  [Wallet] 状态初始化完成！(Base Ready)");
    }

    // 仅在 share_addr 时调用
    pub fn prepare_reception_for_sharing(&mut self, pp: &PP) -> Fr {
        if let Some(ref base) = self.base {
            // 基于 Base 生成新的 Reception
            let (new_recv, r_delta) = WalletReceptionState::from_base(base, pp);
            self.reception = Some(new_recv);
            println!("  [Wallet] 接收地址已重随机化 (New r_delta)");
            r_delta
        } else {
            Fr::zero()
        }
    }

    // [发送方] 更新本地 Base 和 Pending 余额
    pub fn apply_update_as_sender(&mut self, new_ac: AuthCommitment, new_total: U256, _pp: &PP) {
        self.pending_amount = new_total; 
        if let Some(ref mut base) = self.base {
            base.ac = new_ac; 
        }
        // Base 变了，旧 Reception 失效，清空以强制下次 share_addr 重新生成
        self.reception = None; 
        println!("  [Wallet] (发送方) 本地状态已更新，余额: {} wei", self.pending_amount);
    }

    // [接收方] 收到 P2P 转账 -> 去随机化 -> 存入 Buffer
    pub fn buffer_incoming_update(&mut self, randomized_ac: AuthCommitment, amt: U256, pp: &PP) {
        println!("  [Wallet] 收到转账，正在处理...");
        
        // 1. 尝试获取去随机化所需的 r_delta
        // 如果 reception 为空 (没 share 过)，这里会 panic 或失败。
        // 正常流程是：share_addr -> 对方 send -> 我收到。所以 reception 应该有值。
        if let Some(ref recv) = self.reception {
            let r_delta = recv.r_delta;
            
            // 2. 去随机化
            let canonical_ac = unrandomize(randomized_ac.c, &randomized_ac.sigma, r_delta, pp);
            
            // 3. 存入 Buffer
            let item = EpochUpdateItem {
                commitment: ecp_to_base64(canonical_ac.c),
                signature: zksig_to_base64(&canonical_ac.sigma),
                amount_hex: format!("{:x}", amt),
            };
            self.epoch_buffer.push(item);
            
            // 4. 更新累计收入 (仅记录，不进 pending_amount，防止双重消费)
            self.current_epoch_income += amt;
            
            // 5. 更新 Base (为了支持连续接收)
            // 假设下一次接收基于这次的结果
            if let Some(ref mut base) = self.base {
                base.ac = canonical_ac;
            }
            
            println!("  [Wallet] 交易存入 Epoch Buffer。本轮暂收: +{} wei", self.current_epoch_income);
        } else {
            println!("  ⚠️ [Error] 无法去随机化：本地 Reception 状态缺失");
        }
    }

    // [结算] 收到 EPOCH_ACK
    pub fn settle_epoch(&mut self) {
        println!("  [Wallet] --- 执行 Epoch 结算 ---");
        println!("  [Wallet] 初始主余额: {}", self.amount);
        println!("  [Wallet] 本轮发送扣除: -{}", self.amount - self.pending_amount); // 假设 pending <= amount
        println!("  [Wallet] 本轮接收收入: +{}", self.current_epoch_income);
        
        // 新余额 = (扣除后的 Pending) + (本轮收入)
        self.amount = self.pending_amount + self.current_epoch_income;
        
        // 重置状态
        self.pending_amount = self.amount;
        self.current_epoch_income = U256::ZERO;
        let count = self.epoch_buffer.len();
        self.epoch_buffer.clear();
        
        println!("  [Wallet] 结算完成！最新余额: {} wei (归档 {} 笔接收)", self.amount, count);
    }
}