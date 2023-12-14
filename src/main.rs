use std::path::PathBuf;

use clap::Parser;
use curve25519_dalek::Scalar;
use rand::prelude::*;
use rayon::prelude::*;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};

#[derive(Parser)]
struct Opt {
    starts_with: String,
    #[clap(long, short, default_value = "hs_ed25519_secret_key")]
    out: PathBuf,
}

fn main() {
    let opt = Opt::parse();

    let starts_with = base32_mask(&opt.starts_with);
    let matcher = BitMatcher::new(starts_with, 5 * opt.starts_with.len());

    let now = std::time::Instant::now();
    for i in 1.. {
        const NUM_ITER: usize = 100_000;
        let num_threads = std::thread::available_parallelism().unwrap().get();
        if let Some(secret) = (0..num_threads).into_par_iter().find_map_any(|_| {
            let mut rng = SmallRng::from_entropy();
            let mut seed = [0u8; 32];

            for _ in 0..NUM_ITER {
                // Currently using a strict way to generate secret key
                rng.fill_bytes(&mut seed);
                let secret = Sha512::new().chain_update(&seed).finalize();
                let public_key = gen_public_key(secret[..32].try_into().unwrap());
                if matcher.is_match(&public_key) {
                    return Some(secret);
                }
            }
            None
        }) {
            let public_key = gen_public_key(secret[..32].try_into().unwrap());
            let mut contents = Vec::new();
            contents.extend_from_slice(b"== ed25519v1-secret: type0 ==\x00\x00\x00");
            contents.extend_from_slice(&secret);
            std::fs::write(&opt.out, contents).unwrap();
            println!("found: {}", url_from_public_key(&public_key));
            println!("secret key have saved to {}", opt.out.display());
            break;
        } else {
            let num_tried = i * NUM_ITER * num_threads;

            println!(
                "Tried {} keys in {} seconds. {} keys/sec. Overall {} bits.",
                num_tried,
                now.elapsed().as_secs_f32(),
                num_tried as f32 / now.elapsed().as_secs_f32(),
                (num_tried as f32).log2()
            );
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

struct BitMatcher {
    starts_with: Vec<u8>,
    len_bits: usize,
}

impl BitMatcher {
    fn new(starts_with: Vec<u8>, len_bits: usize) -> Self {
        Self {
            starts_with,
            len_bits,
        }
    }

    #[inline(always)]
    fn is_match(&self, public_key: &[u8; 32]) -> bool {
        if public_key[..self.len_bits / 8] != self.starts_with[..self.len_bits / 8] {
            return false;
        }

        if self.len_bits % 8 == 0 {
            true
        } else {
            let mask = 255 << (8 - (self.len_bits % 8));
            public_key[self.len_bits / 8] & mask == self.starts_with[self.len_bits / 8] & mask
        }
    }
}

#[inline(always)]
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
    data_encoding::BASE32.encode(&data).to_lowercase() + ".onion"
}
