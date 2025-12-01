use rand::{Rng, RngCore};
use std::ops::{Add, Mul, Sub};
use std::fmt;

// ==========================================
// 第一部分：基础设施 (Wrappers)
// ==========================================

pub mod wrapper {
    use super::*;
    use blst::*;

    // --- 标量域 (Fr) ---
    #[derive(Clone, Copy, PartialEq)]
    pub struct Fr(pub blst_fr);

    impl fmt::Debug for Fr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Fr({})", self.to_hex())
        }
    }

    impl Fr {
        pub fn from_u64(val: u64) -> Self {
            let mut bytes = [0u8; 32];
            let val_bytes = val.to_le_bytes(); 
            for i in 0..8 { bytes[i] = val_bytes[i]; }
            let mut scalar = unsafe { blst_scalar::default() };
            unsafe { blst_scalar_from_le_bytes(&mut scalar, bytes.as_ptr(), 32) };
            let mut ret = unsafe { blst_fr::default() };
            unsafe { blst_fr_from_scalar(&mut ret, &scalar) };
            Fr(ret)
        }

        pub fn to_hex(&self) -> String {
            let mut scalar = unsafe { blst_scalar::default() };
            unsafe { blst_scalar_from_fr(&mut scalar, &self.0) };
            let mut bytes = [0u8; 32];
            unsafe { blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar) };
            hex::encode(bytes)
        }

        pub fn from_hex(s: &str) -> Result<Self, String> {
            let bytes = hex::decode(s).map_err(|e| e.to_string())?;
            if bytes.len() != 32 { return Err("Invalid Fr hex length".into()); }
            let mut scalar = unsafe { blst_scalar::default() };
            unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
            let mut ret = unsafe { blst_fr::default() };
            unsafe { blst_fr_from_scalar(&mut ret, &scalar) };
            Ok(Fr(ret))
        }

        pub fn random() -> Self {
            let mut rng = rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            let mut scalar = unsafe { blst_scalar::default() };
            unsafe { blst_scalar_from_le_bytes(&mut scalar, ikm.as_ptr(), 32) };
            let mut ret = unsafe { blst_fr::default() };
            unsafe { blst_fr_from_scalar(&mut ret, &scalar) };
            Fr(ret)
        }

        pub fn zero() -> Self { Fr(unsafe { blst_fr::default() }) }
        
        pub fn inverse(&self) -> Self {
            let mut ret = unsafe { blst_fr::default() };
            unsafe { blst_fr_eucl_inverse(&mut ret, &self.0) };
            Fr(ret)
        }
    }

    // --- G1 群 ---
    #[derive(Clone, Copy)]
    pub struct G1(pub blst_p1);

    impl fmt::Debug for G1 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "G1({})", self.to_hex())
        }
    }

    impl G1 {
        pub fn generator() -> Self { unsafe { G1(*blst_p1_generator()) } }
        pub fn is_infinity(&self) -> bool {
            let mut p_aff = unsafe { blst_p1_affine::default() };
            unsafe { blst_p1_to_affine(&mut p_aff, &self.0) };
            unsafe { blst_p1_affine_is_inf(&p_aff) }
        }
        pub fn to_hex(&self) -> String {
            let mut bytes = [0u8; 48];
            unsafe { blst_p1_compress(bytes.as_mut_ptr(), &self.0) };
            hex::encode(bytes)
        }
        pub fn from_hex(s: &str) -> Result<Self, String> {
            let bytes = hex::decode(s).map_err(|e| e.to_string())?;
            if bytes.len() != 48 { return Err("Invalid G1 hex length".into()); }
            let mut p1 = unsafe { blst_p1::default() };
            let mut p1_aff = unsafe { blst_p1_affine::default() };
            let err = unsafe { blst_p1_uncompress(&mut p1_aff, bytes.as_ptr()) };
            if err != BLST_ERROR::BLST_SUCCESS { return Err("G1 uncompress failed".into()); }
            unsafe { blst_p1_from_affine(&mut p1, &p1_aff) };
            Ok(G1(p1))
        }
    }

    // --- G2 群 ---
    #[derive(Clone, Copy)]
    pub struct G2(pub blst_p2);

    impl fmt::Debug for G2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "G2({})", self.to_hex())
        }
    }

    impl G2 {
        pub fn generator() -> Self { unsafe { G2(*blst_p2_generator()) } }
        pub fn to_hex(&self) -> String {
            let mut bytes = [0u8; 96];
            unsafe { blst_p2_compress(bytes.as_mut_ptr(), &self.0) };
            hex::encode(bytes)
        }
        pub fn from_hex(s: &str) -> Result<Self, String> {
            let bytes = hex::decode(s).map_err(|e| e.to_string())?;
            if bytes.len() != 96 { return Err("Invalid G2 hex length".into()); }
            let mut p2 = unsafe { blst_p2::default() };
            let mut p2_aff = unsafe { blst_p2_affine::default() };
            let err = unsafe { blst_p2_uncompress(&mut p2_aff, bytes.as_ptr()) };
            if err != BLST_ERROR::BLST_SUCCESS { return Err("G2 uncompress failed".into()); }
            unsafe { blst_p2_from_affine(&mut p2, &p2_aff) };
            Ok(G2(p2))
        }
    }

    // --- 运算符重载 ---
    impl Add for Fr { type Output = Fr; fn add(self, rhs: Self) -> Self::Output { let mut ret = unsafe { blst_fr::default() }; unsafe { blst_fr_add(&mut ret, &self.0, &rhs.0) }; Fr(ret) } }
    impl Mul for Fr { type Output = Fr; fn mul(self, rhs: Self) -> Self::Output { let mut ret = unsafe { blst_fr::default() }; unsafe { blst_fr_mul(&mut ret, &self.0, &rhs.0) }; Fr(ret) } }
    
    impl Sub for Fr { 
        type Output = Fr; 
        fn sub(self, rhs: Self) -> Self::Output { 
            let mut ret = unsafe { blst_fr::default() }; 
            unsafe { blst_fr_sub(&mut ret, &self.0, &rhs.0) }; 
            Fr(ret) 
        } 
    }

    impl Add for G1 { type Output = G1; fn add(self, rhs: Self) -> Self::Output { let mut ret = unsafe { blst_p1::default() }; unsafe { blst_p1_add(&mut ret, &self.0, &rhs.0) }; G1(ret) } }
    
    impl Sub for G1 {
        type Output = G1;
        fn sub(self, rhs: Self) -> Self::Output {
            let mut rhs_neg = rhs.0;
            unsafe { blst_p1_cneg(&mut rhs_neg, true) }; 
            let mut ret = unsafe { blst_p1::default() };
            unsafe { blst_p1_add(&mut ret, &self.0, &rhs_neg) };
            G1(ret)
        }
    }

    impl Mul<Fr> for G1 { type Output = G1; fn mul(self, rhs: Fr) -> Self::Output { let mut ret = unsafe { blst_p1::default() }; let mut scalar = unsafe { blst_scalar::default() }; unsafe { blst_scalar_from_fr(&mut scalar, &rhs.0) }; unsafe { blst_p1_mult(&mut ret, &self.0, scalar.b.as_ptr(), 255) }; G1(ret) } }
    impl PartialEq for G1 { fn eq(&self, other: &Self) -> bool { unsafe { blst_p1_is_equal(&self.0, &other.0) } } }

    impl Mul<Fr> for G2 { type Output = G2; fn mul(self, rhs: Fr) -> Self::Output { let mut ret = unsafe { blst_p2::default() }; let mut scalar = unsafe { blst_scalar::default() }; unsafe { blst_scalar_from_fr(&mut scalar, &rhs.0) }; unsafe { blst_p2_mult(&mut ret, &self.0, scalar.b.as_ptr(), 255) }; G2(ret) } }

    // --- 配对函数 ---
    pub fn pairing(p2: G2, p1: G1) -> blst_fp12 {
        let mut p1_aff = unsafe { blst_p1_affine::default() };
        let mut p2_aff = unsafe { blst_p2_affine::default() };
        unsafe { blst_p1_to_affine(&mut p1_aff, &p1.0) };
        unsafe { blst_p2_to_affine(&mut p2_aff, &p2.0) };
        let mut res = unsafe { blst_fp12::default() };
        unsafe { blst_miller_loop(&mut res, &p2_aff, &p1_aff) };
        let mut final_res = unsafe { blst_fp12::default() };
        unsafe { blst_final_exp(&mut final_res, &res) };
        final_res
    }
    pub fn fp12_eq(a: &blst_fp12, b: &blst_fp12) -> bool { unsafe { blst_fp12_is_equal(a, b) } }
    pub fn fp12_mul(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 { let mut ret = unsafe { blst_fp12::default() }; unsafe { blst_fp12_mul(&mut ret, a, b) }; ret }
}

use wrapper::*;

// ==========================================
// 第二部分：RSUC 协议实现
// ==========================================

#[derive(Clone, Debug)]
pub struct PP { pub g1: G1, pub p: G1, pub g2: G2 }
#[derive(Clone, Debug)]
pub struct KeyPair { pub sk: Fr, pub vk: G2 }
#[derive(Clone, Debug)]
pub struct ZKSig { pub z: G1, pub s: G1, pub s_hat: G2, pub t: G1 }
#[derive(Clone, Debug)]
pub struct AuthCommitment { pub c: G1, pub sigma: ZKSig }

pub fn setup() -> PP {
    println!("[RSUC] 正在执行 Setup...");
    let g1 = G1::generator();
    let g2 = G2::generator();
    let r = Fr::random();
    let p = g1 * r;
    PP { g1, p, g2 }
}

pub fn key_gen(pp: &PP) -> KeyPair {
    println!("[RSUC] 正在执行 KeyGen...");
    let sk = Fr::random();
    let vk = pp.g2 * sk;
    KeyPair { sk, vk }
}

pub fn auth_com(v: Fr, x: Fr, r: Fr, pp: &PP) -> AuthCommitment {
    println!("[RSUC] 正在执行 AuthCom (生成承诺)...");
    let c = (pp.g1 * v) + (pp.p * r);
    let s = Fr::random(); 
    let s_inv = s.inverse();
    let z = ((pp.g1 + (c * x)) * s_inv);
    let sigma = ZKSig { z, s: pp.g1 * s, s_hat: pp.g2 * s, t: pp.p * x * s_inv };
    AuthCommitment { c, sigma }
}

pub fn vf_com(c: G1, v: Fr, r: Fr, pp: &PP) -> bool {
    println!("[RSUC] 正在执行 VfCom (验证承诺)...");
    c == (pp.g1 * v) + (pp.p * r)
}

pub fn vf_auth(c: G1, sigma: &ZKSig, vk: G2, pp: &PP) -> bool {
    println!("[RSUC] 正在执行 VfAuth (验证零知识证明)...");
    if sigma.s.is_infinity() { return false; }
    let ch1 = fp12_eq(&pairing(sigma.s_hat, sigma.z), &fp12_mul(&pairing(pp.g2, pp.g1), &pairing(vk, c)));
    let ch2 = fp12_eq(&pairing(sigma.s_hat, pp.g1), &pairing(pp.g2, sigma.s));
    let ch3 = fp12_eq(&pairing(sigma.s_hat, sigma.t), &pairing(vk, pp.p));
    ch1 && ch2 && ch3
}

pub fn rdm_ac(c: G1, sigma: &ZKSig, r_p: Fr, pp: &PP) -> AuthCommitment {
    println!("[RSUC] 正在执行 RdmAC (随机化承诺)...");
    let c_new = c + (pp.p * r_p);
    let s_p = Fr::random(); 
    let s_inv = s_p.inverse();
    let z_new = (sigma.z + (sigma.t * r_p)) * s_inv;
    AuthCommitment { 
        c: c_new, 
        sigma: ZKSig { z: z_new, s: sigma.s * s_p, s_hat: sigma.s_hat * s_p, t: sigma.t * s_inv } 
    }
}

pub fn upd_ac(c: G1, a: Fr, x: Fr, pp: &PP) -> AuthCommitment {
    println!("[RSUC] 正在执行 UpdAC (同态更新)...");
    let c_new = c + (pp.g1 * a);
    let s = Fr::random(); 
    let s_inv = s.inverse();
    let z = ((pp.g1 + (c_new * x)) * s_inv);
    let sigma = ZKSig { z, s: pp.g1 * s, s_hat: pp.g2 * s, t: pp.p * x * s_inv };
    AuthCommitment { c: c_new, sigma }
}

pub fn vf_upd(c: G1, a: Fr, c_new: G1, sigma_new: &ZKSig, vk: G2, pp: &PP) -> bool {
    println!("[RSUC] 正在执行 VfUpd (验证更新)...");
    let expected_c_new = c + (pp.g1 * a);
    if expected_c_new != c_new { return false; }
    vf_auth(c_new, sigma_new, vk, pp)
}

pub fn unrandomize(c_new: G1, sigma_new: &ZKSig, r_prime: Fr, pp: &PP) -> AuthCommitment {
    println!("[RSUC] 正在执行 Unrandomize (去随机化)...");
    let c = c_new - (pp.p * r_prime);
    let z = sigma_new.z - (sigma_new.t * r_prime);
    let sigma = ZKSig { z, s: sigma_new.s, s_hat: sigma_new.s_hat, t: sigma_new.t };
    AuthCommitment { c, sigma }
}

// ==========================================
// [关键修复] 批量更新 & 验证
// ==========================================

// 批量更新: C* = Sum(Ci) + C_sender - k * C_base
pub fn batch_verify_update(
    sender_c: G1,             // [修复] 第一个参数是 Sender 当前状态 (Operator最新存储)
    base_c: G1,               // [修复] 第二个参数是 Base 状态 (接收交易的基准)
    updates: Vec<(G1, ZKSig)>, 
    sk: Fr, 
    vk: G2,                   
    pp: &PP
) -> Option<AuthCommitment> {
    println!("[RSUC] 正在执行 Batch Update (聚合更新 + 验证)...");
    
    let k = updates.len();
    
    // 1. 验证所有接收方更新的合法性
    let mut c_sum = sender_c; // 初始值设为 C_sender

    for (c, sig) in updates {
        // 对每一笔收到的款项，Operator 必须验证其签名有效性
        if !vf_auth(c, &sig, vk, pp) {
            println!("  ❌ 批量验证失败: 发现非法承诺/签名");
            return None;
        }
        c_sum = c_sum + c;
    }

    // 2. 计算聚合承诺: C* = (Sender_C + Sum(Recv_C)) - k * Base_C
    let mut c_star = c_sum;
    if k > 0 {
        let k_fr = Fr::from_u64(k as u64);
        let k_base = base_c * k_fr; // 这里的 base_c 现在正确对应了基准承诺
        c_star = c_star - k_base;
    }

    // 3. 生成新签名
    Some(auth_com_from_c(c_star, sk, pp))
}

// 辅助: 已知 C，生成签名 (不涉及 v 和 r)
fn auth_com_from_c(c: G1, x: Fr, pp: &PP) -> AuthCommitment {
    let s = Fr::random(); 
    let s_inv = s.inverse();
    let z = ((pp.g1 + (c * x)) * s_inv);
    let sigma = ZKSig { z, s: pp.g1 * s, s_hat: pp.g2 * s, t: pp.p * x * s_inv };
    AuthCommitment { c, sigma }
}

// ==========================================
// 工具函数 (保持不变)
// ==========================================
pub mod utils {
    use super::wrapper::*;
    use super::*;
    use sha2::{Sha256, Digest};
    use base64::{Engine as _, engine::general_purpose};

    pub fn ecp_to_base64(p: G1) -> String { general_purpose::STANDARD.encode(hex::decode(p.to_hex()).unwrap()) }
    pub fn ecp_from_base64(s: &str) -> Result<G1, String> {
        let bytes = general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())?;
        G1::from_hex(&hex::encode(bytes))
    }
    pub fn ecp2_to_base64(p: G2) -> String { general_purpose::STANDARD.encode(hex::decode(p.to_hex()).unwrap()) }
    pub fn ecp2_from_base64(s: &str) -> Result<G2, String> {
        let bytes = general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())?;
        G2::from_hex(&hex::encode(bytes))
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct ZKSigJson { z: String, s: String, s_hat: String, t: String }
    pub fn zksig_to_base64(sig: &ZKSig) -> String {
        let json = ZKSigJson { z: sig.z.to_hex(), s: sig.s.to_hex(), s_hat: sig.s_hat.to_hex(), t: sig.t.to_hex() };
        general_purpose::STANDARD.encode(serde_json::to_string(&json).unwrap())
    }
    pub fn zksig_from_base64(s: &str) -> Result<ZKSig, String> {
        let bytes = general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())?;
        let json: ZKSigJson = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(ZKSig { z: G1::from_hex(&json.z)?, s: G1::from_hex(&json.s)?, s_hat: G2::from_hex(&json.s_hat)?, t: G1::from_hex(&json.t)? })
    }

    pub fn hash256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn xor_r(r: Fr, key: &[u8]) -> Vec<u8> {
        println!("[Crypto] 正在执行 XOR 加密/解密...");
        let r_hex = r.to_hex();
        let r_bytes = hex::decode(r_hex).unwrap(); 
        let mut out = vec![0u8; r_bytes.len()];
        for i in 0..r_bytes.len() {
            out[i] = r_bytes[i] ^ key[i % key.len()];
        }
        out
    }

    pub fn recover_r_from_bytes(bytes: &[u8]) -> Fr {
        println!("[Crypto] 正在执行数据恢复 (Bytes -> Fr)...");
        if bytes.len() != 32 { return Fr::zero(); }
        let hex_str = hex::encode(bytes);
        Fr::from_hex(&hex_str).unwrap_or(Fr::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::*;

    #[test]
    fn test_data_integrity() {
        println!("--- 数据完整性测试 ---");
        let r_origin = Fr::random();
        let key = hash256(b"test_key");
        let cipher = xor_r(r_origin, &key);
        let mut recovered_bytes = vec![0u8; 32];
        for i in 0..32 { recovered_bytes[i] = cipher[i] ^ key[i % key.len()]; }
        let r_recovered = recover_r_from_bytes(&recovered_bytes);
        assert_eq!(r_origin.to_hex(), r_recovered.to_hex());
        println!("✅ Fr 数据完整性测试通过");
    }
}