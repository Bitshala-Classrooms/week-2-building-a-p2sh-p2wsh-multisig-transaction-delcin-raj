use std::str::FromStr;

use bitcoin::absolute::{Height, LockTime};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::ecdsa;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_0;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, ScriptBuf, Transaction, TxIn,
    TxOut, Txid, Witness, PublicKey
};
mod raj;
use secp256k1::{Message, Secp256k1, SecretKey};
fn main() {
    let private_key_1 = PrivateKey::from_slice(
        &<[u8; 32]>::from_hex("39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf")
            .unwrap(),
        Network::Bitcoin,
    )
    .unwrap();
    let privkey_1 =
        SecretKey::from_str("39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf")
            .unwrap();

    let test_priv_key = PrivateKey::new(privkey_1, Network::Bitcoin);

    assert_eq!(private_key_1, test_priv_key);

    let private_key_2 = PrivateKey::from_slice(
        &<[u8; 32]>::from_hex("5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d")
            .unwrap(),
        Network::Bitcoin,
    )
    .unwrap();

    let address: Address<NetworkUnchecked> = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF".parse().unwrap();
    let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();

    let redeem_script = ScriptBuf::from_hex("5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae").unwrap();

    let txin = TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: Witness::new(),
    };

    let spending_amount = Amount::from_sat(100_000);
    let txout = TxOut {
        value: spending_amount,
        script_pubkey: address.script_pubkey(),
    };

    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::Blocks(Height::from_consensus(0).unwrap()),
        input: vec![txin.clone()],
        output: vec![txout],
    };
    let secp = Secp256k1::new();

    // Calculate the sighash and sign with both private keys
    let mut sig_hash_cache = SighashCache::new(&tx);
    let sighash = sig_hash_cache
        .p2wsh_signature_hash(0, &redeem_script, spending_amount, EcdsaSighashType::All)
        .unwrap();
    let digest = sighash.to_byte_array();
    let message = Message::from_digest(digest);
    let sig1 = secp.sign_ecdsa(&message, &private_key_1.inner);
    let sig2 = secp.sign_ecdsa(&message, &private_key_2.inner);

    // Create the script_sig
    // let sig1_71 = <[u8; 71]>::try_from(sig1.serialize_der().as_ref()).unwrap();
    // let sig2_71 = <[u8; 70]>::try_from(sig2.serialize_der().as_ref()).unwrap();

    let e_sig1 = ecdsa::Signature::sighash_all(sig1);
    let e_sig2 = ecdsa::Signature::sighash_all(sig2);

    let mut script_sig = ScriptBuf::new();
    let mut push_bytes = PushBytesBuf::new();
    push_bytes
        .extend_from_slice(redeem_script.to_p2wsh().as_bytes())
        .unwrap();
    script_sig.push_slice(push_bytes);

    // Create the witness stack
    let mut witness_stack = Witness::new();
    witness_stack.push(Vec::new());
    witness_stack.push_ecdsa_signature(&e_sig2);
    witness_stack.push_ecdsa_signature(&e_sig1);
    witness_stack.push(redeem_script);

    // Update the transaction with the script_sig and witness stack
    let txin_final = TxIn {
        previous_output: txin.previous_output,
        script_sig,
        sequence: txin.sequence,
        witness: witness_stack,
    };

    let tx_final = Transaction {
        version: tx.version,
        lock_time: tx.lock_time,
        input: vec![txin_final],
        output: tx.output,
    };

      // Obtain the public keys from the private keys
    let public_key_1 = PublicKey::from_private_key(&Secp256k1::new(), &private_key_1);
    let public_key_2 = PublicKey::from_private_key(&Secp256k1::new(), &private_key_2);

    let secp = Secp256k1::verification_only();
    let is_sig1_valid = secp.verify_ecdsa(
        &message,
        &sig1,
        &public_key_1.inner,
    ).is_ok();
    let is_sig2_valid = secp.verify_ecdsa(
        &message,
        &sig2,
        &public_key_2.inner,
    ).is_ok();

    println!("Signature 1 Valid: {}", is_sig1_valid);
    println!("Signature 2 Valid: {}", is_sig2_valid);

    // Write the transaction hex to out.txt
    let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx_final));
    std::fs::write("out.txt", tx_hex).expect("Unable to write file");
}
