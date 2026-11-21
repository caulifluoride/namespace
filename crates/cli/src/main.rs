//! `ns`: a wallet for namespace names. Holds one key, builds and signs
//! transactions, and talks to a node's local RPC. Also builds the Bitcoin
//! side: the covenant chain, and the transactions that anchor blocks to it.

mod covenant;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, rand};
use bitcoin::{Address, Amount, Network, OutPoint, Psbt, ScriptBuf, TxOut};
use clap::{Args as ClapArgs, Parser, Subcommand};
use namespace_core::tx::{SignedOp, commitment_hash, sighash, sign};
use namespace_core::{Encode, Hash256, Name, NameProof, NameRecord, OwnerKey, Tx};
use serde_json::Value;

use crate::covenant::ChainFile;

#[derive(Parser)]
#[command(name = "ns", about = "Namespace wallet")]
struct Args {
    /// Node RPC address.
    #[arg(long, global = true, default_value = "http://127.0.0.1:7340")]
    node: String,
    /// Secret key file. Salts for pending registrations are kept next to it.
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new key.
    Keygen,
    /// Print this wallet's owner key.
    Pubkey,
    /// Show the node's status.
    Status,
    /// Look up who owns a name.
    Lookup { name: Name },
    /// Fetch a proof of a name's record and check it against the node's
    /// state root.
    Proof { name: Name },
    /// Step 1 of registering: commit to a name without revealing it.
    Commit { name: Name },
    /// Step 2 of registering: reveal a committed name.
    Register { name: Name },
    /// Extend a name's expiry.
    Renew { name: Name },
    /// Give a name to another owner key.
    Transfer { name: Name, new_owner: OwnerKey },
    /// Ask the node to build a block from its mempool, for anchoring.
    Build,
    /// Build a block and the Bitcoin transaction that anchors it, as a PSBT
    /// for your Bitcoin wallet to sign.
    Anchor(AnchorArgs),
    /// Finalize a signed anchoring PSBT and print the package to broadcast.
    Finalize {
        /// The signed PSBT, base64.
        psbt: String,
    },
    /// Create the covenant chain (done once, by whoever launches the chain).
    #[command(subcommand)]
    Covenant(CovenantCmd),
}

#[derive(Subcommand)]
enum CovenantCmd {
    /// Step 1: create the covenant key and print the address to fund.
    Keygen {
        /// Where to keep the key until `sign` deletes it.
        #[arg(long)]
        key_out: PathBuf,
        #[arg(long, default_value_t = Network::Bitcoin)]
        network: Network,
    },
    /// Step 2: once the address is funded, sign the chain and delete the key.
    Sign {
        #[arg(long)]
        key: PathBuf,
        /// The output that funded the address, `txid:vout`.
        #[arg(long)]
        funding: OutPoint,
        /// Its amount, in sats. Carried along the whole chain.
        #[arg(long)]
        amount: u64,
        /// Covenant transactions to sign: one per anchored block.
        #[arg(long)]
        count: u32,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(ClapArgs)]
struct AnchorArgs {
    /// The covenant chain file from `ns covenant sign`.
    #[arg(long)]
    chain: PathBuf,
    /// A UTXO of yours that pays the fee, `txid:vout`. P2TR or P2WPKH.
    #[arg(long)]
    utxo: OutPoint,
    /// Its amount, in sats.
    #[arg(long)]
    utxo_amount: u64,
    /// Its address.
    #[arg(long)]
    utxo_address: Address<NetworkUnchecked>,
    /// Where the rest of the UTXO goes.
    #[arg(long)]
    change: Address<NetworkUnchecked>,
    /// Fee rate for the covenant transaction and the child together, sat/vB.
    #[arg(long)]
    fee_rate: f64,
    #[arg(long, default_value_t = Network::Bitcoin)]
    network: Network,
}

struct Wallet {
    key_path: PathBuf,
    node: String,
    http: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key_path = match args.key {
        Some(p) => p,
        None => default_key_path()?,
    };
    let w = Wallet {
        key_path,
        node: args.node.trim_end_matches('/').to_owned(),
        http: reqwest::Client::new(),
    };

    match args.cmd {
        Cmd::Keygen => w.keygen()?,
        Cmd::Pubkey => println!("{}", owner(&w.keypair()?)),
        Cmd::Status => print_json(&w.get("/status").await?.context("no status")?),
        Cmd::Lookup { name } => match w.get(&format!("/name/{name}")).await? {
            Some(record) => print_json(&record),
            None => println!("{name} is not registered"),
        },
        Cmd::Proof { name } => w.proof(name).await?,
        Cmd::Commit { name } => w.commit(name).await?,
        Cmd::Register { name } => w.register(name).await?,
        Cmd::Renew { name } => {
            let kp = w.keypair()?;
            let rec = w.record(&name).await?;
            let digest = sighash(&name, rec.registered_at, rec.seq, SignedOp::Renew);
            let tx = Tx::Renew {
                name,
                seq: rec.seq,
                sig: sign(&kp, &digest),
            };
            w.submit(&tx).await?;
        }
        Cmd::Transfer { name, new_owner } => {
            let kp = w.keypair()?;
            let rec = w.record(&name).await?;
            let op = SignedOp::Transfer {
                new_owner: &new_owner,
            };
            let digest = sighash(&name, rec.registered_at, rec.seq, op);
            let tx = Tx::Transfer {
                name,
                new_owner,
                seq: rec.seq,
                sig: sign(&kp, &digest),
            };
            w.submit(&tx).await?;
        }
        Cmd::Build => print_json(&w.build().await?),
        Cmd::Anchor(a) => w.anchor(a).await?,
        Cmd::Finalize { psbt } => finalize(&psbt)?,
        Cmd::Covenant(CovenantCmd::Keygen { key_out, network }) => {
            covenant_keygen(&key_out, network)?
        }
        Cmd::Covenant(CovenantCmd::Sign {
            key,
            funding,
            amount,
            count,
            out,
        }) => covenant_sign(&key, funding, Amount::from_sat(amount), count, &out)?,
    }
    Ok(())
}

fn covenant_keygen(path: &Path, network: Network) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    write_private(path, &sk.display_secret().to_string())?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let address = Address::from_script(&covenant::covenant_script(&secp, &kp), network)?;
    println!("{address}");
    eprintln!(
        "fund this address with one output (at least {} sats), then run `ns covenant sign`",
        covenant::MIN_COVENANT_VALUE.to_sat()
    );
    Ok(())
}

fn covenant_sign(
    key: &Path,
    funding: OutPoint,
    amount: Amount,
    count: u32,
    out: &Path,
) -> Result<()> {
    if out.exists() {
        bail!("{} already exists", out.display());
    }
    let secp = Secp256k1::new();
    let hex_key =
        std::fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
    let sk: SecretKey = hex_key.trim().parse().context("parsing covenant key")?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let txs = covenant::generate(&secp, &kp, funding, amount, count)?;
    let file = ChainFile {
        start: funding,
        value: amount,
        covenant_vout: covenant::COVENANT_VOUT,
        anchor_vout: covenant::ANCHOR_VOUT,
        txs: txs
            .iter()
            .map(bitcoin::consensus::encode::serialize_hex)
            .collect(),
    };
    std::fs::write(out, serde_json::to_string(&file)?)?;
    // The covenant only holds if nobody can sign another spend.
    let len = std::fs::metadata(key)?.len() as usize;
    std::fs::write(key, vec![0u8; len])?;
    std::fs::remove_file(key)?;
    println!(
        "wrote {count} covenant transactions to {}; deleted {}",
        out.display(),
        key.display()
    );
    println!(
        "start nodes with --covenant-start {funding} --covenant-start-height <the height the funding tx confirmed at> \\\n  --covenant-vout {} --anchor-vout {}",
        covenant::COVENANT_VOUT,
        covenant::ANCHOR_VOUT
    );
    Ok(())
}

fn finalize(psbt: &str) -> Result<()> {
    let psbt: Psbt = psbt.trim().parse().context("parsing PSBT")?;
    let child = covenant::finalize(psbt)?;
    println!("{}", bitcoin::consensus::encode::serialize_hex(&child));
    eprintln!("broadcast with the covenant transaction printed by `ns anchor`:");
    eprintln!("  bitcoin-cli submitpackage '[\"<covenant tx>\", \"<this tx>\"]'");
    Ok(())
}

fn default_key_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --key")?;
    Ok(PathBuf::from(home).join(".namespace").join("key"))
}

fn owner(kp: &Keypair) -> OwnerKey {
    kp.x_only_public_key().0
}

fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).expect("json value serializes")
    );
}

async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    bail!(
        "node returned {status}: {}",
        resp.text().await.unwrap_or_default()
    )
}

impl Wallet {
    fn keygen(&self) -> Result<()> {
        if self.key_path.exists() {
            bail!("{} already exists", self.key_path.display());
        }
        if let Some(dir) = self.key_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let sk = SecretKey::new(&mut rand::thread_rng());
        write_private(&self.key_path, &sk.display_secret().to_string())?;
        let kp = Keypair::from_secret_key(&Secp256k1::signing_only(), &sk);
        println!("{}", owner(&kp));
        Ok(())
    }

    fn keypair(&self) -> Result<Keypair> {
        let hex_key = std::fs::read_to_string(&self.key_path)
            .with_context(|| format!("reading {} (run `ns keygen`?)", self.key_path.display()))?;
        let sk: SecretKey = hex_key.trim().parse().context("parsing secret key")?;
        Ok(Keypair::from_secret_key(&Secp256k1::signing_only(), &sk))
    }

    fn salts_path(&self) -> PathBuf {
        self.key_path.with_extension("salts.json")
    }

    fn salts(&self) -> Result<BTreeMap<Name, Hash256>> {
        match std::fs::read_to_string(self.salts_path()) {
            Ok(s) => Ok(serde_json::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_salts(&self, salts: &BTreeMap<Name, Hash256>) -> Result<()> {
        write_private(&self.salts_path(), &serde_json::to_string_pretty(salts)?)
    }

    async fn commit(&self, name: Name) -> Result<()> {
        let kp = self.keypair()?;
        let mut salts = self.salts()?;
        // Reuse the salt if we already committed, so retrying is safe.
        let salt = *salts.entry(name.clone()).or_insert_with(|| {
            let mut s = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
            Hash256(s)
        });
        // Save before submitting: losing the salt means losing the commitment.
        self.save_salts(&salts)?;
        let commitment = commitment_hash(&name, &owner(&kp), &salt);
        self.submit(&Tx::Commit { commitment }).await?;
        println!(
            "committed to {name}; run `ns register {name}` once the commit is a few blocks deep"
        );
        Ok(())
    }

    async fn register(&self, name: Name) -> Result<()> {
        let kp = self.keypair()?;
        let mut salts = self.salts()?;
        let salt = *salts.get(&name).with_context(|| {
            format!("no commitment for {name} in this wallet; run `ns commit {name}`")
        })?;
        let commitment = commitment_hash(&name, &owner(&kp), &salt);
        if self
            .get(&format!("/commitment/{commitment}"))
            .await?
            .is_none()
        {
            bail!("commitment for {name} isn't in the chain yet (or has expired)");
        }
        self.submit(&Tx::Register {
            name: name.clone(),
            owner: owner(&kp),
            salt,
        })
        .await?;
        salts.remove(&name);
        self.save_salts(&salts)?;
        Ok(())
    }

    async fn build(&self) -> Result<Value> {
        let resp = self
            .http
            .post(format!("{}/build", self.node))
            .send()
            .await?;
        Ok(check(resp).await?.json().await?)
    }

    async fn anchor(&self, a: AnchorArgs) -> Result<()> {
        let chain: ChainFile = serde_json::from_str(
            &std::fs::read_to_string(&a.chain)
                .with_context(|| format!("reading {}", a.chain.display()))?,
        )?;
        let utxo_address = a.utxo_address.require_network(a.network)?;
        let change = a.change.require_network(a.network)?;

        let built = self.build().await?;
        let field = |k: &str| {
            built[k]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("node /build response has no {k}"))
        };
        let outpoint: OutPoint = field("covenant_outpoint")?.parse()?;
        let op_return = ScriptBuf::from_hex(&field("op_return")?)?;
        if built["anchor_vout"].as_u64() != Some(u64::from(chain.anchor_vout)) {
            bail!("the node's anchor_vout doesn't match {}", a.chain.display());
        }
        let parent = chain.spending(outpoint)?.with_context(|| {
            format!(
                "no covenant transaction in {} spends {outpoint}",
                a.chain.display()
            )
        })?;

        let psbt = covenant::anchor_child(
            &parent,
            chain.anchor_vout,
            op_return,
            a.utxo,
            TxOut {
                value: Amount::from_sat(a.utxo_amount),
                script_pubkey: utxo_address.script_pubkey(),
            },
            change.script_pubkey(),
            a.fee_rate,
        )?;
        println!("block: {} (height {})", field("hash")?, built["height"]);
        println!(
            "covenant tx: {}",
            bitcoin::consensus::encode::serialize_hex(&parent)
        );
        println!("child psbt: {psbt}");
        eprintln!("sign the PSBT with your wallet (e.g. `bitcoin-cli walletprocesspsbt <psbt>`),");
        eprintln!("then run `ns finalize <signed psbt>` and broadcast both as a package.");
        Ok(())
    }

    /// Checks the proof against the root the node reports. That only shows
    /// the node is self-consistent; a light client would take the root from
    /// a header it trusts.
    async fn proof(&self, name: Name) -> Result<()> {
        let v = self
            .get(&format!("/proof/{name}"))
            .await?
            .context("node has no /proof endpoint")?;
        let root: Hash256 = serde_json::from_value(v["state_root"].clone())?;
        let height = v["height"].as_u64().context("no height in proof")?;
        let proof: NameProof = serde_json::from_value(v.clone())?;
        match proof.verify(&name, &root)? {
            Some(rec) if rec.is_active(height) => print_json(&serde_json::to_value(rec)?),
            Some(rec) => println!("{name} expired at height {}", rec.expires_at),
            None => println!("{name} is not registered"),
        }
        println!("proven against state root {root} at height {height}");
        Ok(())
    }

    async fn record(&self, name: &Name) -> Result<NameRecord> {
        let v = self
            .get(&format!("/name/{name}"))
            .await?
            .with_context(|| format!("{name} is not registered"))?;
        Ok(serde_json::from_value(v)?)
    }

    async fn get(&self, path: &str) -> Result<Option<Value>> {
        let resp = self.http.get(format!("{}{path}", self.node)).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(check(resp).await?.json().await?))
    }

    async fn submit(&self, tx: &Tx) -> Result<()> {
        let body = serde_json::json!({ "tx": hex::encode(tx.to_bytes()) });
        let resp = self
            .http
            .post(format!("{}/tx", self.node))
            .json(&body)
            .send()
            .await?;
        let txid: Hash256 = check(resp).await?.json().await?;
        println!("submitted {txid}");
        Ok(())
    }
}

/// Writes a file only the current user can read.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}
