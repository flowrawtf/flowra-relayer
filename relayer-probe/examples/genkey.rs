// One-shot Solana keypair generator: writes a keypair JSON to the given path
// and prints its base58 pubkey. Usage: cargo run -p relayer-probe --example genkey -- <out_path>
use solana_keypair::{write_keypair_file, Keypair};
use solana_signer::Signer;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: genkey <output_keypair_path>");
    let kp = Keypair::new();
    write_keypair_file(&kp, &path).expect("write keypair file");
    // Print only the public key; the secret stays in the file.
    println!("{}", kp.pubkey());
}
