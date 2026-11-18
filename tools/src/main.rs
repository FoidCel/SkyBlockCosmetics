use std::env;
use std::fs;
use std::process;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_compact::{KeyPair, Noise, Seed, Signature};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <sign|verify> [args...]", args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "sign" => {
            if args.len() != 5 {
                eprintln!("usage: {} sign <key.pk8> <input.json> <output.signed.json>", args[0]);
                process::exit(1);
            }
            let key_bytes = fs::read(&args[2]).expect("failed to read private key");
            let seed_bytes = if key_bytes.len() == 48 {
                &key_bytes[16..48]
            } else if key_bytes.len() == 32 {
                &key_bytes[..]
            } else {
                panic!("unexpected key length");
            };

            let seed = Seed::from_slice(seed_bytes).expect("invalid seed");
            let keypair = KeyPair::from_seed(seed);

            let payload = fs::read(&args[3]).expect("failed to read input json");
            let sig = keypair.sk.sign(&payload, Some(Noise::generate()));

            let b64_payload = B64.encode(&payload);
            let b64_sig = B64.encode(sig.as_ref());

            let envelope = format!(
                "{{\"format\":1,\"payload\":\"{}\",\"signature\":\"{}\"}}\n",
                b64_payload, b64_sig
            );
            fs::write(&args[4], envelope).expect("failed to write output");
            println!("signed: {}", args[4]);
        }
        "verify" => {
            if args.len() != 4 {
                eprintln!("usage: {} verify <public.x509> <input.signed.json>", args[0]);
                process::exit(1);
            }
            let pub_bytes = fs::read(&args[2]).expect("failed to read public key");
            let pk_bytes = if pub_bytes.len() == 44 {
                &pub_bytes[12..44]
            } else if pub_bytes.len() == 32 {
                &pub_bytes[..]
            } else {
                panic!("unexpected public key length");
            };
            let pk = ed25519_compact::PublicKey::from_slice(pk_bytes).expect("invalid public key");

            let envelope_raw = fs::read_to_string(&args[3]).expect("failed to read signed json");
            let val: serde_json::Value = serde_json::from_str(&envelope_raw).expect("invalid json");
            let b64_payload = val["payload"].as_str().expect("missing payload");
            let b64_sig = val["signature"].as_str().expect("missing signature");

            let payload = B64.decode(b64_payload).expect("invalid base64 payload");
            let sig_bytes = B64.decode(b64_sig).expect("invalid base64 sig");
            let sig = Signature::from_slice(&sig_bytes).expect("invalid signature bytes");

            pk.verify(&payload, &sig).expect("signature verification failed");
            println!("signature valid");
        }
        _ => {
            eprintln!("unknown command: {}", args[1]);
            process::exit(1);
        }
    }
}
