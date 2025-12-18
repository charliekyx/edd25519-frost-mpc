# EdD25519 FROST MPC Signing Scheme (Solana Example)
This project simulates a threshold signature system based on the FROST (Flexible Round-Optimized Threshold Signatures) protocol. It allows a set of participants (3 in this example) to collaboratively generate a Solana wallet address and perform transactions requiring a minimum threshold of signers (2-of-3).

## Project Structure
### mpc-dkg: Distributed Key Generation (DKG) module. 
Nodes use Feldman’s Verifiable Secret Sharing (VSS) to generate a group public key and individual secret shares without a trusted dealer.


### mpc-signer: Signature generation module. 
It simulates participants cooperating to calculate valid Ed25519 signature shares for a given message.

### solana-sender: Transaction construction and broadcasting module. 
It fetches the recent blockhash from Solana, serializes the transfer instruction, and broadcasts the completed transaction.

### flow.txt
Documentation of the interaction flow between the Coordinator and Signers. For the detailed workflow, please refer to this file.


## How to Run
1. Generate Distributed Keys (DKG)
Navigate to the mpc-dkg directory and run the DKG process to simulate 3 nodes generating a 2-of-3 threshold setup.

```Bash
cd mpc-dkg
cargo run
```
The tool will print a JSON object containing key_package1, key_package2, and pubkey_package.

Setup: Copy this entire JSON output and save it as mpc_keys.json inside the mpc-signer/ directory.


2. Construct the Solana Transaction
In the solana-sender directory, run the utility to prepare the message that needs to be signed.

```Bash
cd solana-sender
cargo run

# Action: The program will connect to the Solana Devnet, fetch a blockhash, and display the Message to Sign (Hex).

# Note: Keep this terminal open; it will wait for you to provide the final signature.
```

3. Generate the MPC Threshold Signature
Open a new terminal window and navigate to the mpc-signer directory.

```Bash

cd mpc-signer
cargo run

# Input: When prompted with Paste the HEX message, paste the Hex string obtained from Step 2.

# Process: The signer will simulate two participants (Node 1 and Node 2) generating their signature shares and aggregating them.

# Output: The program will print the final Signature (Hex).
```


4. Broadcast the Transaction
Return to the terminal where solana-sender is running.

Action: Paste the Signature (Hex) from Step 3 and press Enter.

Result: The application will assemble the transaction, send it to the Solana network, and provide a Tx Hash upon success.