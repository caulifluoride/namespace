mod bitcoin_source;
mod chain;
mod follower;
mod node;
mod rpc;
mod store;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bitcoin::OutPoint;
use clap::{Parser, ValueEnum};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId, SecretKey};
use namespace_core::{CovenantConfig, Params};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::bitcoin_source::{BitcoinCore, BitcoinSource, Esplora};
use crate::chain::Chain;
use crate::node::{ALPN, Node, Protocol};
use crate::store::Store;

#[derive(Parser)]
#[command(name = "namespaced", about = "Namespace full node")]
struct Args {
    #[arg(long, default_value = "./namespace-data")]
    data_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7340")]
    rpc_addr: SocketAddr,
    /// Endpoint ids of peers to connect to. Can be repeated. More peers are
    /// found through these, and remembered across restarts.
    #[arg(long = "peer")]
    peers: Vec<EndpointId>,
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,

    #[arg(long, value_enum)]
    bitcoin_backend: Backend,
    /// URL of the Bitcoin backend.
    #[arg(long)]
    bitcoin_url: String,
    /// `user:password` for Bitcoin Core RPC.
    #[arg(long)]
    bitcoin_auth: Option<String>,

    /// The outpoint the first covenant transaction spends, as `txid:vout`.
    #[arg(long)]
    covenant_start: OutPoint,
    /// The first Bitcoin height that can contain a covenant transaction.
    #[arg(long)]
    covenant_start_height: u32,
    #[arg(long, default_value_t = 0)]
    covenant_vout: u32,
    #[arg(long, default_value_t = 1)]
    anchor_vout: u32,
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Regtest,
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Core,
    Esplora,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,iroh=warn".into()),
        )
        .init();
    let args = Args::parse();

    let url = args.bitcoin_url.clone();
    match args.bitcoin_backend {
        Backend::Core => {
            let auth = args
                .bitcoin_auth
                .as_deref()
                .map(|a| {
                    let (u, p) = a
                        .split_once(':')
                        .context("--bitcoin-auth must be user:password")?;
                    anyhow::Ok((u.to_owned(), p.to_owned()))
                })
                .transpose()?;
            run(args, BitcoinCore::new(url, auth)?).await
        }
        Backend::Esplora => run(args, Esplora::new(url)?).await,
    }
}

async fn run<S: BitcoinSource>(args: Args, source: S) -> Result<()> {
    std::fs::create_dir_all(&args.data_dir)?;
    let params = match args.network {
        Network::Mainnet => Params::mainnet(),
        Network::Regtest => Params::regtest(),
    };
    let covenant = CovenantConfig {
        start: args.covenant_start,
        start_height: args.covenant_start_height,
        covenant_vout: args.covenant_vout,
        anchor_vout: args.anchor_vout,
    };

    let store = Store::open(&args.data_dir.join("chain.redb"))?;
    let chain = Chain::load(params, covenant, &store)?;
    info!(
        height = chain.state().height(),
        tip = %chain.state().tip(),
        "loaded chain"
    );

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(load_or_create_key(&args.data_dir.join("iroh.key"))?)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    info!(endpoint_id = %endpoint.id(), "p2p endpoint bound");

    let node = Node::new(chain, store, endpoint.clone(), args.peers)?;
    let router = Router::builder(endpoint)
        .accept(ALPN, Protocol(node.clone()))
        .spawn();

    tokio::spawn(follower::run(node.clone(), source));
    tokio::spawn(node.clone().run_discovery());

    let listener = tokio::net::TcpListener::bind(args.rpc_addr).await?;
    info!(addr = %args.rpc_addr, "rpc listening");
    let server = axum::serve(listener, rpc::router(node.clone()));

    tokio::select! {
        r = server => r?,
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    router.shutdown().await?;
    // So the next start doesn't replay what this run applied.
    node.chain().save_snapshot(&node.store)?;
    Ok(())
}

/// The node's p2p identity, kept across restarts so peers can find it.
fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if let Ok(hex_key) = std::fs::read_to_string(path) {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key.trim(), &mut bytes)
            .with_context(|| format!("parsing {}", path.display()))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    std::fs::write(path, hex::encode(key.to_bytes()))?;
    Ok(key)
}
