use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, message::Message,
    pubkey::Pubkey, signature::Signature, system_instruction, transaction::Transaction,
};
use std::str::FromStr;

fn main() {
    // 1. 设置 MPC 钱包地址
    let mpc_wallet_str = "CGAPvNmgyY9TSQMUye4ityNZViGww1DRSCCM5k8NZZYS";
    let mpc_wallet = Pubkey::from_str(mpc_wallet_str).unwrap();

    println!("--- 步骤 1: 构造交易 ---");
    let rpc_url = "https://api.devnet.solana.com";
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("正在获取最新 Blockhash...");
    let recent_blockhash = client
        .get_latest_blockhash()
        .expect("无法连接 Solana 网络获取 Blockhash"); // Solana 的交易必须包含一个“最近的区块哈希”，相当于一个“有效期时间戳”。
    println!("获取成功: {:?}", recent_blockhash);

    // 构造转账
    let recipient = Pubkey::from_str("2GTBJcGhhLjcNevbSDtAkjmeDpcRLAW2kwUCuAseiAsm").unwrap();
    let instruction = system_instruction::transfer(&mpc_wallet, &recipient, 1_000_000);
    let message = Message::new_with_blockhash(&[instruction], Some(&mpc_wallet), &recent_blockhash);

    // 序列化消息
    let message_data = message.serialize();
    let message_hex = hex::encode(&message_data);

    println!("待签名消息 (Hex):");
    println!("{}", message_hex);
    println!("--------------------------------------------------");
    println!("请复制上面的 Hex 字符串，粘贴到 mpc-signer 中进行签名。");
    println!("--------------------------------------------------");

    // 这里模拟暂停，等待用户输入签名
    println!("请输入 MPC 计算出的签名 (Hex):");
    let mut signature_input = String::new();
    std::io::stdin().read_line(&mut signature_input).unwrap();
    let signature_hex = signature_input.trim();

    if signature_hex.is_empty() {
        return;
    }

    // 2. 组装并广播
    let signature_bytes = hex::decode(signature_hex).expect("无效的 Hex");
    let solana_signature = Signature::try_from(signature_bytes.as_slice()).expect("签名长度错误");

    let mut tx = Transaction::new_unsigned(message);
    tx.signatures = vec![solana_signature];

    println!("正在发送交易...");
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("成功! Tx Hash: {}", sig),
        Err(e) => println!("发送失败 (可能是余额不足或签名错误): {:?}", e),
    }
}

// https://solscan.io/tx/GsawaLY6Nq89QmQaLL311Ns7ENWdK648xAcwbfJJy8qAim2gsefvygXNFt27RVPKYh5PBy534pCQZcr2Gj4eeBN?cluster=devnet