use crate::crypto::RSUC::{self, AuthCommitment, PP, rdm_ac, upd_ac};
use crate::crypto::RSUC::wrapper::{Fr, G1, G2};
use crate::crypto::RSUC::utils::ecp_to_base64; // 用于打印
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
    // [新增] 记录这次随机化使用的增量随机数，用于去随机化
    pub r_delta: Fr, 
}

impl WalletReceptionState {
    // 从基础状态派生接收状态 (带随机化)
    // 返回: (新状态, 使用的随机数 r_delta)
    pub fn from_base(base: &WalletBaseState, pp: &PP) -> (Self, Fr) {
        let r_delta = Fr::random(); 
        // C_recv = C_base + r_delta * P
        let new_ac = rdm_ac(base.ac.c, &base.ac.sigma, r_delta, pp);
        (Self { ac: new_ac, r: r_delta, r_delta }, r_delta)
    }

    pub fn rerandomize(&self, pp: &PP) -> (Self, Fr) {
        let r_delta = Fr::random();
        let new_ac = rdm_ac(self.ac.c, &self.ac.sigma, r_delta, pp);
        (Self { ac: new_ac, r: r_delta, r_delta }, r_delta)
    }
}

#[derive(Clone, Debug)]
pub struct UserWallet {
    // 当前 Epoch 开始时的确认余额
    pub amount: U256, 
    
    // [新增] 待结算的余额 (Epoch 机制占位)
    // 交易发生后，更新这个值，但暂不更新 amount
    pub pending_amount: U256,

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
            pending_amount: amt, // 初始时 pending = amount
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

    // [修改 1] 初始化时不进行随机化，reception 直接指向 base 的拷贝 (r_delta=0)
    // 或者 reception 为空，强制用户先 share_addr (推荐后者)
    pub fn init_from_operator(&mut self, ac: AuthCommitment, r: Fr, _pp: &PP) {
        println!("  [Wallet] 正在初始化本地钱包状态...");
        
        // 打印详细数据 (需求 2)
        println!("    > Base Commitment: {}", ecp_to_base64(ac.c));
        // println!("    > Base Signature:  {}", zksig_to_base64(&ac.sigma)); // 需引入utils

        let base = WalletBaseState { ac, r };
        self.base = Some(base);
        // reception 留空，直到 share_addr 时生成
        self.reception = None; 
        
        println!("  [Wallet] 状态初始化完成！(Base State Ready)");
    }

    // [修改 1] 仅在 share_addr 时随机化，并记录随机数
    pub fn prepare_reception_for_sharing(&mut self, pp: &PP) -> Fr {
        if let Some(ref base) = self.base {
            // 每次 share 都基于 base 重新生成一个新的随机化地址
            let (new_recv, r_delta) = WalletReceptionState::from_base(base, pp);
            
            // 打印随机化后的数据 (需求 2)
            println!("    > Randomized Com: {}", ecp_to_base64(new_recv.ac.c));
            println!("    > Random Factor r_delta: {:?}", r_delta);

            self.reception = Some(new_recv);
            r_delta
        } else {
            Fr::zero()
        }
    }

    // [修改 3] Epoch 机制：不更新 amount，只更新 pending_amount
    pub fn apply_update_pending(&mut self, new_ac: AuthCommitment, new_pending_amt: U256, _pp: &PP) {
        // 1. 更新待结算余额
        self.pending_amount = new_pending_amt;

        // 2. 更新基础状态 (Base必须实时更新以支持连续交易)
        if let Some(ref mut base) = self.base {
            println!("    > Updating Base Com: {}", ecp_to_base64(new_ac.c));
            base.ac = new_ac; 
        }

        // 3. 清空 Reception (因为它基于旧 Base)，迫使下次 share_addr 重新生成
        self.reception = None;

        println!("  [Wallet] 交易完成。Pending 余额更新为: {} wei (Epoch 结算前主余额保持 {})", 
                 self.pending_amount, self.amount);
    }

    // [新增] 结算 Epoch (占位)
    pub fn end_epoch(&mut self) {
        self.amount = self.pending_amount;
        println!("  [Wallet] Epoch 结算完成。主余额已同步: {} wei", self.amount);
        // 这里未来需要添加向 Operator 发送最终状态的逻辑
    }
}