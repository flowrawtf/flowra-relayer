//! relayer-probe: feasibility test for subscribing to an upstream Jito(-compatible) relayer.
//!
//! Authenticates to a relayer's AuthService as a VALIDATOR (challenge -> sign -> tokens),
//! then calls Relayer::SubscribePackets and counts packets/heartbeats for a fixed window.
//!
//! Purpose: prove whether an external relayer (e.g. Jito's public mainnet relayer) will
//! authorize our validator identity and actually stream packets. Run this on a box with
//! egress to the relayer AND the validator identity keypair (e.g. the Frankfurt validator box).
//!
//! Example:
//!   relayer-probe --url http://frankfurt.mainnet.relayer.jito.wtf:8100 \
//!                 --keypair-path /home/sol/validator-keypair.json --secs 30
//!
//! Exit signal is in the printed lines: "AUTH OK" then "SUBSCRIBED" then a RESULT rate.
//! A permission_denied at the challenge/token step means that relayer will NOT serve us.

use std::{path::PathBuf, time::{Duration, Instant}};

use clap::Parser;
use jito_protos::{
    auth::{
        auth_service_client::AuthServiceClient, GenerateAuthChallengeRequest,
        GenerateAuthTokensRequest, Role,
    },
    relayer::{
        relayer_client::RelayerClient, subscribe_packets_response::Msg, SubscribePacketsRequest,
    },
};
use solana_keypair::read_keypair_file;
use solana_signer::Signer;
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

#[derive(Parser, Debug)]
#[command(about = "Probe whether an upstream relayer will auth our validator and stream packets")]
struct Args {
    /// Relayer URL, e.g. http://frankfurt.mainnet.relayer.jito.wtf:8100 (use https:// for TLS)
    #[arg(long)]
    url: String,

    /// Path to the validator IDENTITY keypair (must be a validator the relayer authorizes)
    #[arg(long)]
    keypair_path: PathBuf,

    /// How many seconds to count the packet stream
    #[arg(long, default_value = "30")]
    secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let kp = read_keypair_file(&args.keypair_path)
        .map_err(|e| format!("failed to read keypair {:?}: {e}", args.keypair_path))?;
    let pubkey = kp.pubkey();
    eprintln!("[*] identity pubkey: {pubkey}");
    eprintln!("[*] connecting to {}", args.url);

    let mut endpoint = Endpoint::from_shared(args.url.clone())?
        .tcp_keepalive(Some(Duration::from_secs(15)))
        .connect_timeout(Duration::from_secs(10));
    if args.url.starts_with("https") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new())?;
    }
    let channel: Channel = endpoint.connect().await?;

    // 1) challenge
    let mut auth = AuthServiceClient::new(channel.clone());
    let challenge = auth
        .generate_auth_challenge(GenerateAuthChallengeRequest {
            role: Role::Validator as i32,
            pubkey: pubkey.to_bytes().to_vec(),
        })
        .await
        .map_err(|e| format!("GenerateAuthChallenge FAILED ({}): {}", e.code(), e.message()))?
        .into_inner()
        .challenge;
    eprintln!("[*] got challenge (relayer accepted our pubkey for challenge)");

    // 2) sign "{pubkey}-{challenge}" (server verifies exactly this)
    let to_sign = format!("{pubkey}-{challenge}");
    let sig = kp.sign_message(to_sign.as_bytes());

    // 3) tokens
    let tokens = auth
        .generate_auth_tokens(GenerateAuthTokensRequest {
            challenge: to_sign,
            client_pubkey: pubkey.to_bytes().to_vec(),
            signed_challenge: sig.as_ref().to_vec(),
        })
        .await
        .map_err(|e| format!("GenerateAuthTokens FAILED ({}): {}", e.code(), e.message()))?
        .into_inner();
    let access = tokens.access_token.ok_or("no access token in response")?.value;
    eprintln!("[+] AUTH OK — access token received ({} chars)", access.len());

    // 4) subscribe with Bearer token
    let bearer = format!("Bearer {access}");
    let mut relayer = RelayerClient::with_interceptor(channel, move |mut req: Request<()>| {
        let v: MetadataValue<_> = bearer
            .parse()
            .map_err(|_| tonic::Status::internal("bad bearer token"))?;
        req.metadata_mut().insert("authorization", v);
        Ok(req)
    });

    let mut stream = relayer
        .subscribe_packets(SubscribePacketsRequest {})
        .await
        .map_err(|e| format!("SubscribePackets FAILED ({}): {}", e.code(), e.message()))?
        .into_inner();
    eprintln!("[+] SUBSCRIBED — counting for {}s ...", args.secs);

    let start = Instant::now();
    let (mut batches, mut packets, mut heartbeats) = (0u64, 0u64, 0u64);
    while start.elapsed() < Duration::from_secs(args.secs) {
        match tokio::time::timeout(Duration::from_secs(5), stream.message()).await {
            Ok(Ok(Some(resp))) => match resp.msg {
                Some(Msg::Batch(b)) => {
                    batches += 1;
                    packets += b.packets.len() as u64;
                }
                Some(Msg::Heartbeat(_)) => heartbeats += 1,
                None => {}
            },
            Ok(Ok(None)) => {
                eprintln!("[!] stream closed by server");
                break;
            }
            Ok(Err(e)) => {
                eprintln!("[!] stream error ({}): {}", e.code(), e.message());
                break;
            }
            Err(_) => { /* 5s idle tick, keep waiting */ }
        }
    }

    let secs = start.elapsed().as_secs_f64().max(1.0);
    println!(
        "RESULT over {:.0}s: batches={batches} packets={packets} heartbeats={heartbeats}  => {:.0} packets/s",
        secs,
        packets as f64 / secs
    );
    if packets == 0 {
        eprintln!("[!] 0 packets. Either not near this identity's leader slot, or relayer streams only heartbeats to us.");
    }
    Ok(())
}
