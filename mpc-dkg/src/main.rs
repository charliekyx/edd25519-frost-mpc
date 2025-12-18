use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use std::collections::BTreeMap;
use frost::keys::dkg::{part1, part2, part3};
use serde::{Serialize};


// FROST 的 part1, part2, part3遵循的是Feldman VSS 协议
// 整个过程可以理解为Shamir secret sharing的验签版本
// round1，生成commitment并广播， 从一个多项式开始 f(x) = a_0 + a_1 * x  => (a_0 *  G, a_1 * G) => (C0 , C1)， 这一步将密钥映射到椭圆曲线上
// round2: 分发 share_i = f(i) = a_0 + a_1 * (i)
// round3: 验证 share_i * G ?= C_0 + (i * C_1)


// 文档链接和具体的实现参考
// https://datatracker.ietf.org/doc/rfc9591/

// C.2.  Verifiable Secret Sharing
//    Feldman's Verifiable Secret Sharing (VSS) [FeldmanSecretSharing]
//    builds upon Shamir secret sharing, adding a verification step to
//    demonstrate the consistency of a participant's share with a public
//    commitment to the polynomial f for which the secret s is the constant
//    term.  This check ensures that all participants have a point (their
//    share) on the same polynomial, ensuring that they can reconstruct the
//    correct secret later.

//    The procedure for committing to a polynomial f of degree at most
//    MIN_PARTICIPANTS-1 is as follows.

//    Inputs:
//    - coeffs, a vector of the MIN_PARTICIPANTS coefficients that
//      uniquely determine a polynomial f.

//    Outputs:
//    - vss_commitment, a vector commitment to each of the coefficients in
//      coeffs, where each item of the vector commitment is an Element.

//    def vss_commit(coeffs):
//      vss_commitment = []
//      for coeff in coeffs:
//        A_i = G.ScalarBaseMult(coeff)
//        vss_commitment.append(A_i)
//      return vss_commitment

//    The procedure for verification of a participant's share is as
//    follows.  If vss_verify fails, the participant MUST abort the
//    protocol, and the failure should be investigated out of band.

//    Inputs:
//    - share_i: A tuple of the form (i, sk_i), where i indicates the
//      participant identifier (a NonZeroScalar), and sk_i the
//      participant's secret key, a secret share of the constant term of f,
//      where sk_i is a Scalar.
//    - vss_commitment, a VSS commitment to a secret polynomial f, a vector
//      commitment to each of the coefficients in coeffs, where each
//      element of the vector commitment is an Element.

//    Outputs:
//    - True if sk_i is valid, and False otherwise.

//    def vss_verify(share_i, vss_commitment)
//      (i, sk_i) = share_i
//      S_i = G.ScalarBaseMult(sk_i)
//      S_i' = G.Identity()
//      for j in range(0, MIN_PARTICIPANTS):
//        S_i' += G.ScalarMult(vss_commitment[j], pow(i, j))
//      return S_i == S_i'

//    We now define how the Coordinator and participants can derive group
//    info, which is an input into the FROST signing protocol.

//    Inputs:
//    - MAX_PARTICIPANTS, the number of shares to generate, an integer.
//    - MIN_PARTICIPANTS, the threshold of the secret sharing scheme,
//      an integer.
//    - vss_commitment, a VSS commitment to a secret polynomial f, a vector
//      commitment to each of the coefficients in coeffs, where each
//      element of the vector commitment is an Element.

//    Outputs:
//    - PK, the public key representing the group, an Element.
//    - participant_public_keys, a list of MAX_PARTICIPANTS public keys
//      PK_i for i=1,...,MAX_PARTICIPANTS, where each PK_i is the public
//      key, an Element, for participant i.

//    def derive_group_info(MAX_PARTICIPANTS, MIN_PARTICIPANTS,
//     vss_commitment):
//      PK = vss_commitment[0]
//      participant_public_keys = []
//      for i in range(1, MAX_PARTICIPANTS+1):
//        PK_i = G.Identity()
//        for j in range(0, MIN_PARTICIPANTS):
//          PK_i += G.ScalarMult(vss_commitment[j], pow(i, j))
//        participant_public_keys.append(PK_i)
//      return PK, participant_public_keys



fn main() {
    println!("--- 开始分布式密钥生成 (DKG) ---");
    println!("模拟环境: 3 个节点 (Threshold = 2)");
    println!("--------------------------------------------------");

    let mut rng = ThreadRng::default();
    let max_signers = 3;
    let min_signers = 2;

    let id1 = frost::Identifier::try_from(1).unwrap();
    let id2 = frost::Identifier::try_from(2).unwrap();
    let id3 = frost::Identifier::try_from(3).unwrap();

    // =================================================================
    // Round 1
    // =================================================================
    println!("\n[Round 1] 节点生成秘密并广播commitment...");
    let (sec1, pkg1) = part1(id1, max_signers, min_signers, &mut rng).unwrap();
    let (sec2, pkg2) = part1(id2, max_signers, min_signers, &mut rng).unwrap();
    let (sec3, pkg3) = part1(id3, max_signers, min_signers, &mut rng).unwrap();

    let mut round1_packages = BTreeMap::new();
    round1_packages.insert(id1, pkg1);
    round1_packages.insert(id2, pkg2);
    round1_packages.insert(id3, pkg3);

    // =================================================================
    // Round 2
    // =================================================================
    println!("\n[Round 2] 节点交换加密的私钥分片...");

    // 将node i自己在round1 packege中移除， 1只能将2和3输入到round2方法中
    let get_others = |my_id: frost::Identifier| -> BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> {
        let mut others = round1_packages.clone();
        others.remove(&my_id);
        others
    };

    // 执行 Shamir Secret Sharing (SSS) 的切片
    // 它遍历其他人的 ID，代入round1生成的多项式进行计算
    let (sec2_1, shares_sent_by_1) = part2(sec1, &get_others(id1)).unwrap();
    let (sec2_2, shares_sent_by_2) = part2(sec2, &get_others(id2)).unwrap();
    let (sec2_3, shares_sent_by_3) = part2(sec3, &get_others(id3)).unwrap();

    // --- 模拟网络路由 ---
    let mut inbox_1 = BTreeMap::new();
    inbox_1.insert(id2, shares_sent_by_2.get(&id1).unwrap().clone());
    inbox_1.insert(id3, shares_sent_by_3.get(&id1).unwrap().clone());

    let mut inbox_2 = BTreeMap::new();
    inbox_2.insert(id1, shares_sent_by_1.get(&id2).unwrap().clone());
    inbox_2.insert(id3, shares_sent_by_3.get(&id2).unwrap().clone());
    
    let mut inbox_3 = BTreeMap::new();
    inbox_3.insert(id1, shares_sent_by_1.get(&id3).unwrap().clone());
    inbox_3.insert(id2, shares_sent_by_2.get(&id3).unwrap().clone());

    // =================================================================
    // Round 3
    // =================================================================
    println!("\n[Round 3] 计算最终 KeyPackage...");

    let (key_package1, pubkey_package1) = part3(&sec2_1, &get_others(id1), &inbox_1).unwrap();
    let (key_package2, _              ) = part3(&sec2_2, &get_others(id2), &inbox_2).unwrap();
    let (_key_package3, _             ) = part3(&sec2_3, &get_others(id3), &inbox_3).unwrap();

    // =================================================================
    // 结果验证与导出
    // =================================================================
    
    let group_pubkey1 = pubkey_package1.verifying_key();
    let group_pubkey2 = key_package2.verifying_key(); // key_package 也可以直接导出 verifying_key

    assert_eq!(group_pubkey1, group_pubkey2, "致命错误：协商出的公钥不一致！");

    let pubkey_bytes = group_pubkey1.serialize();
    let solana_address = bs58::encode(pubkey_bytes).into_string();

    println!("--------------------------------------------------");
    println!("DKG 成功完成！");
    println!("MPC Wallet Address (Solana): {}", solana_address);
    println!("--------------------------------------------------");

    println!("\n[最终用于节点签名的keypackage如下, 复制到 mpc-signer 项目中]");
    
    #[derive(Serialize)]
    struct SavedKeys {
        key_package1: frost::keys::KeyPackage,
        key_package2: frost::keys::KeyPackage,
        pubkey_package: frost::keys::PublicKeyPackage,
    }

    let output = SavedKeys {
        key_package1: key_package1,
        key_package2: key_package2,
        pubkey_package: pubkey_package1, 
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}