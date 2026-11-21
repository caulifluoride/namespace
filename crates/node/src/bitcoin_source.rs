//! Where the node reads Bitcoin blocks from.
//!
//! The node only needs to walk the Bitcoin chain by height and fetch full
//! blocks, so any backend that can do that works.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::consensus::encode::{deserialize, deserialize_hex};
use serde::Deserialize;
use serde_json::{Value, json};

pub trait BitcoinSource: Send + Sync + 'static {
    /// Height of the current Bitcoin tip.
    fn tip_height(&self) -> impl Future<Output = Result<u32>> + Send;
    /// Hash of the block at `height` on the current best chain.
    fn block_hash(&self, height: u32) -> impl Future<Output = Result<bitcoin::BlockHash>> + Send;
    fn block(
        &self,
        hash: bitcoin::BlockHash,
    ) -> impl Future<Output = Result<bitcoin::Block>> + Send;
}

const TIMEOUT: Duration = Duration::from_secs(60);

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(TIMEOUT).build()?)
}

/// Checks that a fetched block is the one asked for, so a backend can't feed
/// us a different block under a hash we trust.
fn check_hash(block: bitcoin::Block, hash: bitcoin::BlockHash) -> Result<bitcoin::Block> {
    if block.block_hash() != hash {
        bail!("backend returned block {} for {hash}", block.block_hash());
    }
    Ok(block)
}

/// Bitcoin Core over JSON-RPC (`getblockcount`, `getblockhash`, `getblock <hash> 0`).
pub struct BitcoinCore {
    url: String,
    auth: Option<(String, String)>,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

impl BitcoinCore {
    pub fn new(url: String, auth: Option<(String, String)>) -> Result<Self> {
        Ok(Self {
            url,
            auth,
            http: http_client()?,
        })
    }

    async fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let body = json!({ "jsonrpc": "1.0", "id": 0, "method": method, "params": params });
        let mut req = self.http.post(&self.url).json(&body);
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("bitcoin core rpc {method}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!("bitcoin core rpc rejected our credentials");
        }
        // Core reports RPC errors with a non-2xx status and a JSON body.
        let resp: RpcResponse = resp
            .json()
            .await
            .with_context(|| format!("bitcoin core rpc {method}: {status}"))?;
        if let Some(err) = resp.error.filter(|e| !e.is_null()) {
            bail!("bitcoin core rpc {method}: {err}");
        }
        let result = resp
            .result
            .ok_or_else(|| anyhow!("bitcoin core rpc {method}: no result"))?;
        Ok(serde_json::from_value(result)?)
    }
}

impl BitcoinSource for BitcoinCore {
    async fn tip_height(&self) -> Result<u32> {
        self.call("getblockcount", json!([])).await
    }

    async fn block_hash(&self, height: u32) -> Result<bitcoin::BlockHash> {
        self.call("getblockhash", json!([height])).await
    }

    async fn block(&self, hash: bitcoin::BlockHash) -> Result<bitcoin::Block> {
        let hex: String = self.call("getblock", json!([hash, 0])).await?;
        check_hash(deserialize_hex(&hex)?, hash)
    }
}

/// An Esplora HTTP API (`/blocks/tip/height`, `/block-height/:h`, `/block/:hash/raw`).
pub struct Esplora {
    url: String,
    http: reqwest::Client,
}

impl Esplora {
    pub fn new(url: String) -> Result<Self> {
        Ok(Self {
            url: url.trim_end_matches('/').to_owned(),
            http: http_client()?,
        })
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let resp = self
            .http
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .with_context(|| format!("esplora {path}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("esplora {path}: {status}: {}", body.trim());
        }
        Ok(resp)
    }

    async fn text(&self, path: &str) -> Result<String> {
        Ok(self.get(path).await?.text().await?.trim().to_owned())
    }
}

impl BitcoinSource for Esplora {
    async fn tip_height(&self) -> Result<u32> {
        let s = self.text("/blocks/tip/height").await?;
        s.parse()
            .with_context(|| format!("esplora tip height {s:?}"))
    }

    async fn block_hash(&self, height: u32) -> Result<bitcoin::BlockHash> {
        let s = self.text(&format!("/block-height/{height}")).await?;
        s.parse()
            .with_context(|| format!("esplora block hash {s:?}"))
    }

    async fn block(&self, hash: bitcoin::BlockHash) -> Result<bitcoin::Block> {
        let bytes = self
            .get(&format!("/block/{hash}/raw"))
            .await?
            .bytes()
            .await?;
        check_hash(deserialize(&bytes)?, hash)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::Path;
    use axum::routing::{get, post};
    use bitcoin::consensus::encode::{serialize, serialize_hex};
    use bitcoin::hashes::Hash;

    use super::*;

    fn test_block() -> bitcoin::Block {
        bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
    }

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn esplora() {
        let block = test_block();
        let hash = block.block_hash();
        let raw = Bytes::from(serialize(&block));
        let router = Router::new()
            .route("/blocks/tip/height", get(|| async { "0" }))
            .route(
                "/block-height/{h}",
                get(move |Path(h): Path<u32>| async move {
                    if h == 0 {
                        Ok(hash.to_string())
                    } else {
                        Err((axum::http::StatusCode::NOT_FOUND, "Block not found"))
                    }
                }),
            )
            .route("/block/{hash}/raw", get(move || async move { raw }));
        let addr = serve(router).await;
        let src = Esplora::new(format!("http://{addr}/")).unwrap();
        assert_eq!(src.tip_height().await.unwrap(), 0);
        assert_eq!(src.block_hash(0).await.unwrap(), hash);
        assert!(src.block_hash(1).await.is_err());
        assert_eq!(src.block(hash).await.unwrap(), block);
        // The backend can't pass off a block under another hash.
        assert!(src.block(bitcoin::BlockHash::all_zeros()).await.is_err());
    }

    #[tokio::test]
    async fn bitcoin_core() {
        let block = test_block();
        let hash = block.block_hash();
        let hex = serialize_hex(&block);
        let router = Router::new().route(
            "/",
            post(
                move |headers: axum::http::HeaderMap, body: String| async move {
                    // "user:pass"
                    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
                    if auth != Some("Basic dXNlcjpwYXNz") {
                        return Err(axum::http::StatusCode::UNAUTHORIZED);
                    }
                    let req: Value = serde_json::from_str(&body).unwrap();
                    let result = match req["method"].as_str().unwrap() {
                        "getblockcount" => json!(0),
                        "getblockhash" => json!(hash),
                        "getblock" => json!(hex),
                        _ => {
                            return Ok(axum::Json(json!({
                                "result": null,
                                "error": { "code": -32601, "message": "Method not found" },
                            })));
                        }
                    };
                    Ok(axum::Json(json!({ "result": result, "error": null })))
                },
            ),
        );
        let addr = serve(router).await;
        let auth = Some(("user".to_owned(), "pass".to_owned()));
        let src = BitcoinCore::new(format!("http://{addr}/"), auth).unwrap();
        assert_eq!(src.tip_height().await.unwrap(), 0);
        assert_eq!(src.block_hash(0).await.unwrap(), hash);
        assert_eq!(src.block(hash).await.unwrap(), block);
        assert!(src.call::<Value>("nope", json!([])).await.is_err());

        let bad = BitcoinCore::new(format!("http://{addr}/"), None).unwrap();
        assert!(bad.tip_height().await.is_err());
    }
}
