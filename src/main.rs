use clap::Parser;
use curve25519_dalek::Scalar;
use rand::prelude::*;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};

#[derive(Parser)]
struct Opt {
    starts_with: String,
}

fn main() {
    let opt = Opt::parse();

    let len = opt.starts_with.len();

    let b = len * 5 / 8;
    let q = (len * 5) % 8;
    let starts_with = base32_mask(&opt.starts_with);
    dbg!(&starts_with);

    let mut rng = SmallRng::from_entropy();

    loop {
        let seed: [u8; 32] = rng.gen();
        let secret = Sha512::new().chain_update(&seed).finalize();
        let public_key = gen_public_key(secret[..32].try_into().unwrap());
        if is_match(&public_key, &starts_with, b, q) {
            let mut contents = Vec::new();
            contents.extend_from_slice(b"== ed25519v1-secret: type0 ==\x00\x00\x00");
            contents.extend_from_slice(&secret);
            std::fs::write("secret", contents).unwrap();
            println!("{}", url_from_public_key(&public_key));
            break;
        }
    }
}

fn base32_mask(encoded: &str) -> Vec<u8> {
    let mut mask = Vec::new();
    let mut bits = 0;
    for c in encoded.chars() {
        let b = match c {
            'a'..='z' => c as u8 - b'a',
            'A'..='Z' => c as u8 - b'A',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => panic!("invalid base32 character"),
        };

        let u = b << 3;
        if bits % 8 == 0 {
            mask.push(u);
        } else {
            mask[bits / 8] |= u >> (bits % 8);
            if (8 - bits % 8) < 5 {
                mask.push(u << (8 - (bits % 8)));
            }
        }
        bits += 5;
    }
    mask
}

fn is_match(public_key: &[u8; 32], starts_with: &[u8], b: usize, q: usize) -> bool {
    if public_key[..b] != starts_with[..b] {
        return false;
    }

    if q == 0 {
        true
    } else {
        let mask = 255 << (8 - q);
        public_key[b] & mask == starts_with[b] & mask
    }
}

fn gen_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    let signing_key = Scalar::from_bytes_mod_order(secret_key);
    let public_key = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &signing_key;
    public_key.compress().to_bytes()
}

fn url_from_public_key(public_key: &[u8; 32]) -> String {
    let mut sum_data = Vec::new();
    sum_data.extend_from_slice(b".onion checksum");
    sum_data.extend_from_slice(public_key);
    sum_data.extend_from_slice(b"\x03");

    let sum = Sha3_256::new().chain_update(&sum_data).finalize();

    let mut data = public_key.to_vec();
    data.extend_from_slice(&sum[..2]);
    data.extend_from_slice(b"\x03");
    data_encoding::BASE32.encode(&data) + ".onion"
}
