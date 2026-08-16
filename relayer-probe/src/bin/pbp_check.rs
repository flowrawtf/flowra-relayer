//! Staging check for per-validator PBP enforcement against a running relayer.
//!
//! Two validator identities authenticate to the same relayer and subscribe to packets. One
//! pushes a policy blocking a program, the other pushes nothing. The same transactions are then
//! sent into the relayer's TPU QUIC port, and what each identity receives is compared.
//!
//! The property under test is the one the whole design exists for: a relayer fronting several
//! validators must drop for each of them by their own rules and never by another's. A test that
//! only ever connects one validator cannot see that being violated.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use jito_protos::{
    auth::{
        auth_service_client::AuthServiceClient, GenerateAuthChallengeRequest,
        GenerateAuthTokensRequest, Role,
    },
    relayer::{relayer_client::RelayerClient, subscribe_packets_response::Msg, SubscribePacketsRequest},
    shared::{InstructionRule, PbpPolicy},
};
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;
use tokio::sync::Mutex;
use tonic::{metadata::MetadataValue, transport::Channel, Request};

#[derive(Parser, Debug)]
#[command(about = "Verify per-validator PBP enforcement on a running relayer")]
struct Args {
    /// Relayer gRPC URL.
    #[arg(long)]
    url: String,
    /// Validator identity that will push a blocking policy.
    #[arg(long)]
    strict_keypair: PathBuf,
    /// Validator identity that pushes nothing.
    #[arg(long)]
    permissive_keypair: PathBuf,
    /// Relayer TPU QUIC socket to inject packets into.
    #[arg(long)]
    tpu_quic: SocketAddr,
    /// Program id the strict validator blocks.
    #[arg(long)]
    blocked_program: String,
    /// Seconds to collect packets after injecting.
    #[arg(long, default_value = "8")]
    secs: u64,
    /// Pad the innocent transactions out to roughly this many bytes. Above 1232 this exercises
    /// SIMD-0296: the stock QUIC config rejects the stream as invalid_stream_size.
    #[arg(long, default_value = "0")]
    pad_to: usize,
}

type AuthedRelayer = RelayerClient<
    tonic::service::interceptor::InterceptedService<
        Channel,
        Box<dyn FnMut(Request<()>) -> Result<Request<()>, tonic::Status> + Send>,
    >,
>;

/// Full challenge/sign/token handshake, then a Relayer client carrying the bearer token.
async fn connect(url: &str, kp: &Keypair) -> Result<AuthedRelayer, Box<dyn std::error::Error>> {
    let channel = Channel::from_shared(url.to_string())?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await?;
    let pubkey = kp.pubkey();

    let mut auth = AuthServiceClient::new(channel.clone());
    let challenge = auth
        .generate_auth_challenge(GenerateAuthChallengeRequest {
            role: Role::Validator as i32,
            pubkey: pubkey.to_bytes().to_vec(),
        })
        .await?
        .into_inner()
        .challenge;
    let to_sign = format!("{pubkey}-{challenge}");
    let sig = kp.sign_message(to_sign.as_bytes());
    let tokens = auth
        .generate_auth_tokens(GenerateAuthTokensRequest {
            challenge: to_sign,
            client_pubkey: pubkey.to_bytes().to_vec(),
            signed_challenge: sig.as_ref().to_vec(),
        })
        .await?
        .into_inner();
    let access = tokens.access_token.ok_or("no access token")?.value;
    let bearer = format!("Bearer {access}");

    let interceptor: Box<dyn FnMut(Request<()>) -> Result<Request<()>, tonic::Status> + Send> =
        Box::new(move |mut req: Request<()>| {
            let v: MetadataValue<_> = bearer
                .parse()
                .map_err(|_| tonic::Status::internal("bad bearer"))?;
            req.metadata_mut().insert("authorization", v);
            Ok(req)
        });
    Ok(RelayerClient::with_interceptor(channel, interceptor))
}

/// Count packets arriving on a subscription until `secs` elapse.
async fn collect(mut client: AuthedRelayer, secs: u64, label: &'static str) -> Arc<Mutex<u64>> {
    let counter = Arc::new(Mutex::new(0u64));
    let out = counter.clone();
    tokio::spawn(async move {
        let Ok(stream) = client.subscribe_packets(SubscribePacketsRequest {}).await else {
            eprintln!("[{label}] subscribe failed");
            return;
        };
        let mut stream = stream.into_inner();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, stream.message()).await {
                Ok(Ok(Some(resp))) => {
                    if let Some(Msg::Batch(b)) = resp.msg {
                        *counter.lock().await += b.packets.len() as u64;
                    }
                }
                Ok(Ok(None)) | Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
    });
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let strict_kp = read_keypair_file(&args.strict_keypair).map_err(|e| format!("{e}"))?;
    let permissive_kp = read_keypair_file(&args.permissive_keypair).map_err(|e| format!("{e}"))?;
    println!("strict     = {}", strict_kp.pubkey());
    println!("permissive = {}", permissive_kp.pubkey());

    let mut strict = connect(&args.url, &strict_kp).await?;
    let mut permissive = connect(&args.url, &permissive_kp).await?;
    println!("[+] both identities authenticated");

    // Only the strict identity pushes a policy. The permissive one deliberately pushes nothing,
    // so if it loses packets the drop came from somebody else's rules.
    let policy = PbpPolicy {
        allow_aggressive_mev: true,
        program_blacklist: vec![args.blocked_program.clone()],
        instruction_blacklist: vec![InstructionRule {
            program_id: args.blocked_program.clone(),
            data_prefixes: vec![],
        }],
        ..Default::default()
    };
    let digest = strict
        .provide_pbp_policy(policy)
        .await?
        .into_inner()
        .policy_digest;
    println!("[+] strict pushed policy, relayer digest = {digest}");
    if digest.is_empty() {
        return Err("relayer returned an empty digest; it is not storing the policy".into());
    }

    let strict_count = collect(strict, args.secs, "strict").await;
    let permissive_count = collect(permissive, args.secs, "permissive").await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("[*] injecting packets into {} ...", args.tpu_quic);
    inject(args.tpu_quic, &args.blocked_program, args.pad_to).await?;

    tokio::time::sleep(Duration::from_secs(args.secs)).await;
    let s = *strict_count.lock().await;
    let p = *permissive_count.lock().await;
    println!("\nstrict (policy blocks the program): {s} packets");
    println!("permissive (no policy):             {p} packets");

    if p == 0 {
        return Err("permissive validator received nothing; the relayer is not forwarding at \
                    all, so this run proves nothing about policy"
            .into());
    }
    if s >= p {
        return Err(format!(
            "strict received {s} >= permissive {p}: its policy was not applied"
        )
        .into());
    }
    println!("\nPASS: the same packets were dropped for one validator and delivered to the other");
    Ok(())
}

/// Send transactions to the relayer's TPU QUIC port: some invoking the blocked program, some not.
async fn inject(
    addr: SocketAddr,
    blocked_program: &str,
    pad_to: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;
    use solana_streamer::nonblocking::testing_utilities::make_client_endpoint_with_local_addr;
    use solana_transaction::{versioned::VersionedTransaction, Transaction};

    let blocked: Pubkey = blocked_program.parse()?;
    let innocent = Pubkey::new_unique();

    let mut wire = Vec::new();
    for (program, count) in [(blocked, 5usize), (innocent, 5)] {
        for _ in 0..count {
            let payer = Keypair::new();
            // Base tx overhead is ~200 bytes, so pad the instruction data to reach the target.
            let data = if pad_to > 0 {
                vec![0xab; pad_to.saturating_sub(200)]
            } else {
                vec![0xde, 0xad, 0xbe, 0xef]
            };
            let tx = Transaction::new_signed_with_payer(
                &[Instruction::new_with_bytes(
                    program,
                    &data,
                    vec![AccountMeta {
                        pubkey: Pubkey::new_unique(),
                        is_signer: false,
                        is_writable: false,
                    }],
                )],
                Some(&payer.pubkey()),
                &[&payer],
                Hash::new_from_array(Pubkey::new_unique().to_bytes()),
            );
            let bytes = bincode::serialize(&VersionedTransaction::from(tx))?;
            wire.push(bytes);
        }
    }

    // Ephemeral local port: the helper's default binds a fixed one, so a second run collides
    // with the first and the handshake never completes.
    let connection = make_client_endpoint_with_local_addr(
        &addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        None,
    )
    .await?;
    for bytes in &wire {
        let mut stream = connection.open_uni().await?;
        stream.write_all(bytes).await?;
        stream.finish()?;
    }
    // finish() only marks the stream complete locally. Dropping the connection here closes it
    // before the server has read the streams, which looks exactly like "sent, never arrived":
    // the server logs the connection and zero streams. Hold it open until the data is out.
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(connection);
    println!(
        "[+] sent {} transactions, sizes {}..{} bytes",
        wire.len(),
        wire.iter().map(Vec::len).min().unwrap_or(0),
        wire.iter().map(Vec::len).max().unwrap_or(0)
    );
    let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
    Ok(())
}
