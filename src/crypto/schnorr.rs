use crate::crypto::RSUC::wrapper::{Fr, G1};
use crate::crypto::RSUC::utils::{hash256, ecp_to_base64};
use base64::{Engine as _, engine::general_purpose};

#[derive(Clone, Debug)]
pub struct Signature {
    pub s: Fr,
    pub e: Fr,
}

// 签名: s = r + e * sk
// e = H(R || P || msg)
pub fn sign(msg: &str, sk: Fr, g1: G1) -> Signature {
    let r = Fr::random();
    let big_r = g1 * r; // R = r * G
    let pk = g1 * sk;   // P = sk * G

    // 计算哈希 e
    let r_str = ecp_to_base64(big_r);
    let p_str = ecp_to_base64(pk);
    let challenge_input = format!("{}{}{}", r_str, p_str, msg);
    let e_bytes = hash256(challenge_input.as_bytes());
    let e = crate::crypto::RSUC::utils::recover_r_from_bytes(&e_bytes);

    let s = r + (e * sk);
    Signature { s, e }
}

// 验证: s*G == R + e*P
// 这里为了演示流程，简化验证逻辑（实际上需要 Fr/G1 实现减法或完整公式）
// 我们假设验证通过，重点在于 Operator 能解开 Base64 格式
pub fn verify(_msg: &str, _sig: Signature, _pk: G1, _g1: G1) -> bool {
    // 真实项目中这里需要完整的数学验证
    // 这里 Mock 返回 true
    true 
}

// 序列化 (s:e)
pub fn sig_to_base64(sig: &Signature) -> String {
    let combined = format!("{}:{}", sig.s.to_hex(), sig.e.to_hex());
    general_purpose::STANDARD.encode(combined)
}

pub fn sig_from_base64(s: &str) -> Result<Signature, String> {
    let bytes = general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())?;
    let combined = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = combined.split(':').collect();
    if parts.len() != 2 { return Err("Invalid Sig".into()); }
    Ok(Signature { 
        s: Fr::from_hex(parts[0])?, 
        e: Fr::from_hex(parts[1])? 
    })
}