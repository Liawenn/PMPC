use crate::crypto::RSUC::{self, AuthCommitment, PP, rdm_ac, upd_ac};
use crate::crypto::RSUC::wrapper::Fr;
use alloy::primitives::U256;
use std::convert::TryInto; // [修正] 引入 TryInto 用于 U256 转 u64

#[derive(Clone, Debug)]
pub struct WalletBaseState {
    pub ac: AuthCommitment,
    pub r: Fr,
}

#[derive(Clone, Debug)]
pub struct WalletReceptionState {
    pub ac: AuthCommitment,
    pub r: Fr,
}

impl WalletReceptionState {
    // 从基础状态派生接收状态 (随机化)
    pub fn from_base(base: &WalletBaseState, pp: &PP) -> Self {
        let new_r = Fr::random(); 
        // C_recv = C_base + r' * P
        let new_ac = rdm_ac(base.ac.c, &base.ac.sigma, new_r, pp);
        Self {
            ac: new_ac,
            r: new_r,
        }
    }

    // 重新随机化接收状态 (用于隐私保护，对应 Java: rerandomize)
    pub fn rerandomize(&self, pp: &PP) -> Self {
        let new_r = Fr::random();
        // 对当前的接收承诺再次进行随机化
        let new_ac = rdm_ac(self.ac.c, &self.ac.sigma, new_r, pp);
        Self {
            ac: new_ac,
            r: new_r,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UserWallet {
    pub amount: U256, // 明文余额
    pub base: Option<WalletBaseState>,
    pub reception: Option<WalletReceptionState>,
}

impl UserWallet {
    pub fn new(amount: u128) -> Self {
        Self {
            amount: U256::from(amount),
            base: None,
            reception: None,
        }
    }

    // 从 Operator 响应初始化 (对应 Java: fromOperatorResponse)
    pub fn init_from_operator(&mut self, ac: AuthCommitment, r: Fr, pp: &PP) {
        println!("  [Wallet] 正在初始化本地钱包状态...");
        let base = WalletBaseState { ac, r };
        // 生成 reception 状态
        let reception = WalletReceptionState::from_base(&base, pp);
        
        self.base = Some(base);
        self.reception = Some(reception);
        println!("  [Wallet] 状态初始化完成！(Reception AC 已生成)");
    }

    // 重新随机化接收地址 (对应 Java: rerandomizeReception)
    pub fn rerandomize_reception(&mut self, pp: &PP) {
        if let Some(ref current_recv) = self.reception {
            self.reception = Some(current_recv.rerandomize(pp));
            println!("  [Wallet] 接收地址已重随机化 (隐私保护)");
        }
    }

    // 应用 Operator 的状态更新 (对应 Java: handleOkUpdate 中的逻辑)
    pub fn apply_update(&mut self, new_ac: AuthCommitment, new_amount: U256, pp: &PP) {
        // 1. 更新余额
        self.amount = new_amount;

        // 2. 更新基础状态
        // User 发起交易时，base.r 通常不变，只更新 Operator 发回的新承诺 C_new
        if let Some(ref mut base) = self.base {
            base.ac = new_ac; 
        }

        // 3. 必须重新生成接收状态 (因为 Base 变了，Reception 必须基于最新的 Base)
        if let Some(ref base) = self.base {
            self.reception = Some(WalletReceptionState::from_base(base, pp));
        }
        println!("  [Wallet] 余额更新为: {} wei", self.amount);
    }

    // 本地模拟更新 (对应 Java: updateBalance)
    // 注意：这需要私钥 sk，通常用于测试或 Operator 端逻辑
    pub fn update_balance_local(&mut self, new_amount: u128, pp: &PP, sk: Fr) {
        let new_amt_u256 = U256::from(new_amount);
        
        // 计算差额
        let delta_fr = if new_amt_u256 >= self.amount {
            let diff = new_amt_u256 - self.amount;
            // [修正] 使用 try_into 转换 U256 -> u64
            let diff_u64: u64 = diff.try_into().unwrap_or(0); 
            Fr::from_u64(diff_u64)
        } else {
            // 暂不支持负数差额的 Fr 转换 (需要 Fr 支持 neg)
            Fr::from_u64(0) 
        };

        if let Some(ref base) = self.base {
            // 1. 更新承诺 (同态加法)
            let new_base_ac = upd_ac(base.ac.c, delta_fr, sk, pp);
            
            // 2. 重随机化 (防止前后状态关联)
            let new_r = Fr::random();
            let final_ac = rdm_ac(new_base_ac.c, &new_base_ac.sigma, new_r, pp);
            
            // 3. 更新本地状态
            self.base = Some(WalletBaseState { ac: final_ac, r: new_r });
            self.reception = Some(WalletReceptionState::from_base(self.base.as_ref().unwrap(), pp));
        }
        self.amount = new_amt_u256;
    }
}