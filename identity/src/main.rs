// Minimal smoke-test binary: generate a keypair, sign a request, verify
// it, then generate an X25519 keypair and round-trip an encrypted
// message. Not a CLI tool — a manual sanity check during this task only.
// PRD.md §4.2 "Identity layer".

use relay_identity::{
    decrypt, encrypt, export_encryption_public_key_hex, export_public_key_hex,
    generate_encryption_keypair, generate_keypair, sign_payload, verify_payload,
    DEFAULT_MAX_REQUEST_AGE_SECS, RequestPayload,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let (private_key, public_key) = generate_keypair();
    println!("generated keypair; private key debug: {:?}", private_key);
    println!("public key (hex): {}", export_public_key_hex(&public_key));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = RequestPayload {
        sender: "vivek".to_string(),
        recipient: "rohan".to_string(),
        request_type: "ask".to_string(),
        timestamp: now,
        nonce: "0123456789abcdef0123456789abcdef".to_string(),
    };

    let (bytes, signature) = sign_payload(&private_key, &payload);
    match verify_payload(
        &bytes,
        &signature,
        &public_key,
        now,
        DEFAULT_MAX_REQUEST_AGE_SECS,
    ) {
        Ok(verified) => println!("verified request from {} (nonce {})", verified.sender, verified.nonce),
        Err(e) => println!("verification failed: {}", e),
    }

    let (recipient_secret, recipient_public) = generate_encryption_keypair();
    println!(
        "generated X25519 encryption keypair; private key debug: {:?}",
        recipient_secret
    );
    println!(
        "encryption public key (hex): {}",
        export_encryption_public_key_hex(&recipient_public)
    );

    let query = b"how do you handle graceful daemon shutdown in Rust?";
    let ciphertext = encrypt(&recipient_public, query).expect("encryption should succeed");
    match decrypt(&recipient_secret, &ciphertext) {
        Ok(plaintext) => println!(
            "round-tripped encrypted query: {}",
            String::from_utf8_lossy(&plaintext)
        ),
        Err(_) => println!("decryption failed"),
    }
}
