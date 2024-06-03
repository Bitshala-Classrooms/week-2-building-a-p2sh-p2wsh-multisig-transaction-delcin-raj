use std::{fs::File, io::Write, str::FromStr};

use bitcoin::{
    absolute::LockTime,
    consensus::serialize,
    ecdsa::Signature,
    hashes::Hash,
    hex::DisplayHex,
    key::Secp256k1,
    script::PushBytesBuf,
    secp256k1::{Message, SecretKey},
    sighash::SighashCache,
    transaction::Version,
    Address, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

fn main() {
    let privkey_1 =
        SecretKey::from_str("39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf")
            .unwrap();
    let privkey_2 =
        SecretKey::from_str("5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d")
            .unwrap();

    // Write your code here
    let prev_txid =
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let prev_out = OutPoint::new(prev_txid, 0);

    let unsigned_input: TxIn = TxIn {
        sequence: Sequence::MAX, // enables absolute locktime
        previous_output: prev_out,
        script_sig: ScriptBuf::new(),
        witness: Witness::new(),
    };

    let output_spk = Address::from_str("325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF")
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let output_amount = Amount::from_btc(0.001).unwrap();

    let output: TxOut = TxOut {
        script_pubkey: output_spk,
        value: output_amount,
    };

    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![unsigned_input],
        output: vec![output],
    };

    // The whole witness script of the swap tx.
    let witness_script = ScriptBuf::from_hex("5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae").unwrap();

    // a p2wsh script pubkey, from the witness_script to set the script_sig field
    let redeem_script = witness_script.to_p2wsh();
    let mut script_sig = ScriptBuf::new();
    let mut push_bytes = PushBytesBuf::new();
    push_bytes
        .extend_from_slice(redeem_script.as_bytes())
        .unwrap();
    script_sig.push_slice(push_bytes);

    // Create signature
    let secp = Secp256k1::new();
    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(
            0,
            &witness_script,
            Amount::from_btc(0.001).unwrap(),
            EcdsaSighashType::All,
        )
        .unwrap();

    let sighash_message = Message::from_digest(*sighash.as_byte_array());
    let signature_1 = secp.sign_ecdsa(&sighash_message, &privkey_1);
    let signature_2 = secp.sign_ecdsa(&sighash_message, &privkey_2);

    let ecdsa_signature_1 = Signature::sighash_all(signature_1);
    let ecdsa_signature_2 = Signature::sighash_all(signature_2);

    // Assemble the witness data
    // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    let mut witness = Witness::new();
    witness.push(Vec::new()); // multisig dummy
    witness.push_ecdsa_signature(&ecdsa_signature_2);
    witness.push_ecdsa_signature(&ecdsa_signature_1);
    witness.push(witness_script);

    // set scriptsig and witness field
    tx.input.get_mut(0).expect("input expected").script_sig = script_sig;
    tx.input.get_mut(0).expect("input expected").witness = witness;

    // Write the tx to out.txt
    let mut file = File::create("out.txt").unwrap();
    writeln!(file, "{}", serialize(&tx).to_lower_hex_string()).unwrap();
}
