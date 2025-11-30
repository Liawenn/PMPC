use crate::crypto::RSUC::wrapper::{Fr as BlstFr, G1 as BlstG1};
use crate::crypto::RSUC::PP;
use base64::{Engine as _, engine::general_purpose};
use bls_bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
// [引入] 确保引入了 G1Affine 和 G1Projective
use blstrs::{G1Projective, Scalar, G1Affine}; 
use group::{Group, Curve, ff::PrimeField, GroupEncoding}; 
use merlin::Transcript;

// ==========================================
// 适配层 (Bridge): blst <-> blstrs
// ==========================================

fn fr_to_scalar(fr: &BlstFr) -> Scalar {
    let hex = fr.to_hex();
    let mut bytes = hex::decode(hex).expect("Invalid Fr hex");
    bytes.reverse(); 
    let arr: [u8; 32] = bytes.try_into().expect("Invalid Fr byte length");
    Option::from(Scalar::from_repr(arr)).expect("Scalar conversion failed")
}

fn g1_to_point(g1: &BlstG1) -> G1Projective {
    let hex = g1.to_hex();
    let bytes = hex::decode(hex).expect("Invalid G1 hex");
    let arr: [u8; 48] = bytes.try_into().expect("Invalid G1 byte length");
    
    // [修复 1] 显式标注类型 Option<G1Affine>，消除歧义
    let affine_opt: Option<G1Affine> = Option::from(G1Affine::from_compressed(&arr));
    let affine = affine_opt.expect("G1 conversion failed");
    G1Projective::from(affine)
}

// ==========================================
// 对外接口
// ==========================================

pub fn generate_proof(
    v: u64, 
    a: u64, 
    r_blst: &BlstFr, 
    pp: &PP
) -> Result<(String, String), String> {
    let r = fr_to_scalar(r_blst);
    let g = g1_to_point(&pp.g1);
    let h = g1_to_point(&pp.p); 

    if v < a { return Err("Underflow: Insufficient balance".into()); }
    let value = v - a;

    let pc_gens = PedersenGens { B: g, B_blinding: h };
    let bp_gens = BulletproofGens::new(64, 1);
    let mut transcript = Transcript::new(b"PMPC_RangeProof");

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        value,
        &r, 
        32, 
    ).map_err(|e| e.to_string())?;

    let proof_bytes = proof.to_bytes();
    let com_bytes = committed_value.to_compressed(); 

    Ok((
        general_purpose::STANDARD.encode(proof_bytes),
        general_purpose::STANDARD.encode(com_bytes)
    ))
}

pub fn verify_proof(
    proof_b64: &str, 
    c_op_str: &str, 
    a: u64, 
    pp: &PP
) -> bool {
    let proof_bytes = match general_purpose::STANDARD.decode(proof_b64) {
        Ok(b) => b, Err(_) => return false,
    };
    
    let proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p, Err(_) => return false,
    };

    // Sender Commitment (C_op)
    let c_op_bytes_blst = match general_purpose::STANDARD.decode(c_op_str) {
        Ok(b) => b, Err(_) => return false,
    };
    if c_op_bytes_blst.len() != 48 { return false; }
    
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&c_op_bytes_blst);
    
    // [修复 2] 显式标注类型 Option<G1Affine>
    let c_op_opt: Option<G1Affine> = Option::from(G1Affine::from_compressed(&arr));
    let c_op = match c_op_opt {
        Some(p) => G1Projective::from(p), 
        None => return false,
    };

    let g = g1_to_point(&pp.g1);
    let h = g1_to_point(&pp.p);

    // 计算 C_target = C_op - a*G
    let adjustment = g * Scalar::from(a);
    
    // 显式标注 c_target 类型 (Projective)
    let c_target: G1Projective = c_op - adjustment;
    
    // 转换回 Affine 进行验证
    let c_target_affine = G1Affine::from(c_target);

    let pc_gens = PedersenGens { B: g, B_blinding: h };
    let bp_gens = BulletproofGens::new(64, 1);
    let mut transcript = Transcript::new(b"PMPC_RangeProof");

    proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &c_target_affine,
        32
    ).is_ok()
}