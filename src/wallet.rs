// 文件: wallet.rs

use crate::crypto::RSUC::{self, AuthCommitment, PP, rdm_ac, upd_ac, unrandomize};
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
}

#[derive(Clone, Debug)]
pub struct UserWallet {
    pub amount: U256,         
    pub pending_amount: U256, 
    pub current_epoch_income: U256, 
    pub epoch_buffer: Vec<EpochUpdateItem>, 

    // [当前动态 Base] 用于发送交易，随 Send 变化
    pub base: Option<WalletBaseState>,
    
    // [新增: 本轮初始 Base] 专门用于生成接收地址和结算汇报，本轮内**恒定不变**
    pub epoch_base: Option<WalletBaseState>,

    pub active_receptions: HashMap<String, Fr>, 
    
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
            current_epoch_income: U256::ZERO,
            epoch_buffer: Vec::new(),
            base: None,
            epoch_base: None, // 初始化为 None
            active_receptions: HashMap::new(),
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
        let base_state = WalletBaseState { ac, r };
        self.base = Some(base_state.clone());
        self.epoch_base = Some(base_state); // 初始化时，两者相同
        self.active_receptions.clear();
        println!("  [Wallet] 状态初始化完成！(Base Ready)");
    }

    pub fn prepare_reception_for_sharing(&mut self, pp: &PP) -> AuthCommitment {
        // [关键] 生成接收地址时，必须基于 epoch_base (本轮初始状态)
        if let Some(ref base) = self.epoch_base {
            let (new_recv, r_delta) = WalletReceptionState::from_base(base, pp);
            let c_str = ecp_to_base64(new_recv.ac.c);
            self.active_receptions.insert(c_str, r_delta);
            println!("  [Wallet] 接收地址已生成并缓存 (r_delta saved)");
            new_recv.ac 
        } else {
            panic!("Wallet not initialized (Join first)");
        }
    }

    pub fn apply_update_as_sender(&mut self, new_ac: AuthCommitment, new_total: U256, _pp: &PP) {
        self.pending_amount = new_total; 
        if let Some(ref mut base) = self.base {
            base.ac = new_ac; 
            // [注意] 这里只更新 self.base (用于下次发送)，绝对不更新 self.epoch_base
        }
        println!("  [Wallet] (发送方) 本地状态已更新，余额: {} wei", self.pending_amount);
    }

    pub fn buffer_incoming_update(&mut self, randomized_ac: AuthCommitment, amt: U256, pp: &PP) {
        println!("  [Wallet] 收到转账，正在处理...");
        
        if self.epoch_base.is_none() {
            println!("  ⚠️ [Error] 钱包未初始化");
            return;
        }

        let amt_u64 = amt.to::<u64>(); 
        
        // [关键] 验证是基于 epoch_base 进行的
        let expected_c = self.epoch_base.as_ref().unwrap().ac.c + (pp.g1 * Fr::from_u64(amt_u64));
        let mut found_r_delta = None;

        for (_key, &r_delta) in &self.active_receptions {
            let candidate_ac = unrandomize(randomized_ac.c, &randomized_ac.sigma, r_delta, pp);
            if ecp_to_base64(candidate_ac.c) == ecp_to_base64(expected_c) {
                found_r_delta = Some((r_delta, candidate_ac));
                break;
            }
        }

        if let Some((_r_delta, canonical_ac)) = found_r_delta {
            // [关键] 汇报时，填入 epoch_base 的承诺
            let epoch_base_c = self.epoch_base.as_ref().unwrap().ac.c;

            let item = EpochUpdateItem {
                commitment: ecp_to_base64(canonical_ac.c),
                signature: zksig_to_base64(&canonical_ac.sigma),
                amount_hex: format!("{:x}", amt),
                base_commitment: ecp_to_base64(epoch_base_c), // 使用恒定的 Epoch Base
            };
            self.epoch_buffer.push(item);
            
            self.current_epoch_income += amt;
            
            println!("  [Wallet] 去随机化成功！存入 Buffer。本轮暂收: +{} wei", self.current_epoch_income);
        } else {
            println!("  ⚠️ [Error] 无法去随机化：未找到匹配的接收地址");
        }
    }

    pub fn settle_epoch(&mut self, remote_update: Option<AuthCommitment>) {
        println!("  [Wallet] --- 执行 Epoch 结算 ---");
        
        let old_bal = self.amount;
        self.amount = self.pending_amount + self.current_epoch_income;
        self.pending_amount = self.amount; 

        println!("  [Wallet] 余额更新: {} -> {} wei", old_bal, self.amount);

        if let Some(ref old_epoch_base) = self.epoch_base {
            // 随机数 r 在本轮内始终未变
            let new_r = old_epoch_base.r; 
            
            if let Some(new_ac) = remote_update {
                let new_state = WalletBaseState {
                    ac: new_ac,
                    r: new_r
                };
                // [关键] 结算后，更新 Base 和 Epoch Base 为最新状态
                self.base = Some(new_state.clone());
                self.epoch_base = Some(new_state);
                println!("  [Wallet] ✅ 状态凭证已更新 (Signature updated)");
            } else {
                 if self.current_epoch_income > U256::ZERO {
                     println!("  ⚠️ [Warning] 有收入但未收到 Operator 凭证!");
                 }
                 // 无更新时，同步状态
                 if let Some(current_base) = &self.base {
                     self.epoch_base = Some(current_base.clone());
                 }
                 println!("  [Wallet] 状态同步完成 (无接收更新)");
            }
        } else {
             println!("  ⚠️ [Error] Base丢失，无法结算");
        }

        self.current_epoch_income = U256::ZERO;
        self.epoch_buffer.clear();
        self.active_receptions.clear();
        
        println!("  [Wallet] 结算完成！");
    }
}