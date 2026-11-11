//! `ns`: a wallet for namespace names. Holds one key, builds and signs
//! transactions, and talks to a node's local RPC.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, rand};
use clap::{Parser, Subcommand};
use namespace_core::tx::{SignedOp, commitment_hash, sighash, sign};
use namespace_core::{Encode, Hash256, Name, NameRecord, OwnerKey, Tx};
use serde_json::Value;

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
        Cmd::Build => {
            let resp = w.http.post(format!("{}/build", w.node)).send().await?;
            print_json(&check(resp).await?.json::<Value>().await?);
        }
    }
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
