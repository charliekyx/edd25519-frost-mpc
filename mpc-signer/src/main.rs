use frost_ed25519 as frost;
use rand::rngs::ThreadRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self};

#[derive(Serialize, Deserialize)]
struct SavedKeys {
    key_package1: frost::keys::KeyPackage,
    key_package2: frost::keys::KeyPackage,
    pubkey_package: frost::keys::PublicKeyPackage,
}

const KEY_FILE: &str = "mpc_keys.json";

fn main() {
    println!("--- FROST MPC Signer CLI ---");
    sign_message();
}

fn sign_message() {
    // 1. Load keys
    let data =
        fs::read_to_string(KEY_FILE).expect("Could not read key file. Run generation first.");
    let keys: SavedKeys = serde_json::from_str(&data).expect("Invalid key file format");
    let mut rng = ThreadRng::default();

    println!("\n--- Signing Mode ---");
    println!("Paste the HEX message (from solana-sender):");

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let message_hex = input.trim();

    if message_hex.is_empty() {
        println!("Error: Empty message.");
        return;
    }

    let message_bytes = match hex::decode(message_hex) {
        Ok(b) => b,
        Err(_) => {
            println!("Error: Invalid HEX string.");
            return;
        }
    };

    let id1 = frost::Identifier::try_from(1).unwrap();
    let id2 = frost::Identifier::try_from(2).unwrap();

    // --- Round 1: Commitments (Double Nonce) ---
    // Each participant generates their secret nonces (d, e) and public commitments (D, E)
    // - 引入 Double Nonce 和 binding factor，预防ros attack
    let (nonces1, comm1) = frost::round1::commit(keys.key_package1.signing_share(), &mut rng);
    let (nonces2, comm2) = frost::round1::commit(keys.key_package2.signing_share(), &mut rng);

    // Collect commitments map (In real network, this is broadcasted)
    let mut comms = BTreeMap::new();
    comms.insert(id1, comm1);
    comms.insert(id2, comm2);

    // --- Round 2: Signature Shares ---
    // Construct the package. This binds the commitments AND the message together.
    let signing_package = frost::SigningPackage::new(comms, &message_bytes);

    // Each participant calculates their signature share z_i
    // The binding factor 'rho' is calculated implicitly here.
    let share1_sign = frost::round2::sign(&signing_package, &nonces1, &keys.key_package1).unwrap();
    let share2_sign = frost::round2::sign(&signing_package, &nonces2, &keys.key_package2).unwrap();

    // --- Aggregation ---
    // Combine z_i values to form the final signature (R, S)
    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(id1, share1_sign);
    signature_shares.insert(id2, share2_sign);

    let frost_signature =
        frost::aggregate(&signing_package, &signature_shares, &keys.pubkey_package).unwrap();

    let signature_hex = hex::encode(frost_signature.serialize());

    // ============================================================

    println!("\nSignature Generated Successfully!");
    println!("--------------------------------------------------");
    println!("{}", signature_hex);
    println!("--------------------------------------------------");
    println!("Copy the above HEX back to solana-sender.");
}
