//! Local HTTP API for wallets and block builders. Bind it to localhost:
//! `/build` lets the caller drive block production.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use namespace_core::anchor::commitment_script;
use namespace_core::encode::Decode;
use namespace_core::{Block, BlockHash, Hash256, Name, NameProof, NameRecord, Tx};
use serde::{Deserialize, Serialize};

use crate::node::Node;

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/name/{name}", get(name))
        .route("/proof/{name}", get(proof))
        .route("/commitment/{hash}", get(commitment))
        .route("/block/{hash}", get(block))
        .route("/tx", post(submit_tx))
        .route("/build", post(build))
        .with_state(node)
}

type AppState = State<Arc<Node>>;

fn error(status: StatusCode, msg: impl ToString) -> Response {
    (status, msg.to_string()).into_response()
}

#[derive(Serialize, Deserialize)]
pub struct Status {
    pub height: u64,
    pub tip: BlockHash,
    pub state_root: Hash256,
    pub next_btc_height: u32,
    pub covenant_outpoint: String,
    pub mempool: usize,
    pub missing_bodies: usize,
    pub endpoint_id: String,
    pub peers: usize,
    pub registration_cap: u32,
}

async fn status(State(node): AppState) -> Json<Status> {
    let chain = node.chain();
    let state = chain.state();
    Json(Status {
        height: state.height(),
        tip: state.tip(),
        state_root: state.state_root(),
        next_btc_height: chain.next_scan_height(),
        covenant_outpoint: chain.covenant_outpoint().to_string(),
        mempool: chain.mempool_len(),
        missing_bodies: chain.missing_bodies().len(),
        endpoint_id: node.endpoint.id().to_string(),
        peers: node.peer_count(),
        registration_cap: chain.params().registration_cap(state.height() + 1),
    })
}

async fn name(
    State(node): AppState,
    Path(name): Path<String>,
) -> Result<Json<NameRecord>, Response> {
    let name = Name::new(&name).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    let chain = node.chain();
    chain
        .state()
        .lookup(&name)
        .copied()
        .map(Json)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "name not registered"))
}

#[derive(Serialize, Deserialize)]
pub struct ProofResponse {
    /// The block whose `state_root` the proof is against.
    pub tip: BlockHash,
    pub height: u64,
    pub state_root: Hash256,
    #[serde(flatten)]
    pub proof: NameProof,
}

/// A proof of a name's record, or of it having none, against the tip's
/// state root. Unlike `/name`, this also returns expired records.
async fn proof(
    State(node): AppState,
    Path(name): Path<String>,
) -> Result<Json<ProofResponse>, Response> {
    let name = Name::new(&name).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    let chain = node.chain();
    let state = chain.state();
    Ok(Json(ProofResponse {
        tip: state.tip(),
        height: state.height(),
        state_root: state.state_root(),
        proof: state.prove_name(&name),
    }))
}

async fn commitment(
    State(node): AppState,
    Path(hash): Path<String>,
) -> Result<Json<u64>, Response> {
    let hash: Hash256 = hash
        .parse()
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    node.chain()
        .state()
        .commitment_height(&hash)
        .map(Json)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "no such commitment"))
}

async fn block(State(node): AppState, Path(hash): Path<String>) -> Result<Json<Block>, Response> {
    let hash: Hash256 = hash
        .parse()
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    let block = node
        .chain()
        .block(&node.store, &hash)
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    block
        .map(Json)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "unknown block"))
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTx {
    /// The transaction in canonical encoding, hex.
    pub tx: String,
}

async fn submit_tx(State(node): AppState, Json(req): Json<SubmitTx>) -> Response {
    let tx = match hex::decode(&req.tx)
        .map_err(|e| e.to_string())
        .and_then(|b| Tx::from_bytes(&b).map_err(|e| e.to_string()))
    {
        Ok(tx) => tx,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let txid = tx.txid();
    match node.submit_tx(tx, None) {
        Ok(()) => Json(txid).into_response(),
        Err(e) => error(StatusCode::UNPROCESSABLE_ENTITY, e),
    }
}

#[derive(Serialize, Deserialize)]
pub struct Built {
    pub hash: BlockHash,
    pub height: u64,
    pub txs: usize,
    /// The covenant output the next covenant transaction spends. Anchor the
    /// block by spending that covenant transaction's anchor output.
    pub covenant_outpoint: String,
    pub anchor_vout: u32,
    /// Script for the anchoring child's OP_RETURN output.
    pub op_return: String,
}

async fn build(State(node): AppState) -> Json<Built> {
    let block = node.build_block();
    let chain = node.chain();
    Json(Built {
        hash: block.hash(),
        height: block.header.height,
        txs: block.txs.len(),
        covenant_outpoint: chain.covenant_outpoint().to_string(),
        anchor_vout: chain.covenant().anchor_vout,
        op_return: hex::encode(commitment_script(&block.hash()).as_bytes()),
    })
}
