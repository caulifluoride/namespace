use bitcoin::secp256k1::{Keypair, Message, Secp256k1, Verification, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};

use crate::encode::{Decode, DecodeError, Encode, Reader};
use crate::hash::Hash256;
use crate::name::Name;

/// A name owner's BIP340 x-only public key.
pub type OwnerKey = XOnlyPublicKey;

/// A namespace transaction. There is no currency, so transactions carry no
/// fees and have no inputs or outputs, only an operation on a name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Tx {
    /// First half of a registration: publishes `commitment_hash(name, owner, salt)`
    /// without revealing the name, so it can't be front-run.
    Commit { commitment: Hash256 },
    /// Second half of a registration: reveals the name, owner and salt
    /// behind a commitment that has aged long enough.
    Register {
        name: Name,
        owner: OwnerKey,
        salt: Hash256,
    },
    /// Extends a name's expiry. Signed by the current owner.
    Renew {
        name: Name,
        seq: u64,
        sig: schnorr::Signature,
    },
    /// Moves a name to a new owner key. Signed by the current owner.
    Transfer {
        name: Name,
        new_owner: OwnerKey,
        seq: u64,
        sig: schnorr::Signature,
    },
}

const TAG_COMMIT: u8 = 0;
const TAG_REGISTER: u8 = 1;
const TAG_RENEW: u8 = 2;
const TAG_TRANSFER: u8 = 3;

/// The hash a `Commit` publishes.
pub fn commitment_hash(name: &Name, owner: &OwnerKey, salt: &Hash256) -> Hash256 {
    let mut buf = Vec::new();
    name.encode(&mut buf);
    buf.extend_from_slice(&owner.serialize());
    salt.encode(&mut buf);
    Hash256::tagged("namespace/commit", &buf)
}

/// What an owner signs to renew or transfer a name.
///
/// `registered_at` ties the signature to one registration of the name, so a
/// signature from a previous owner can't be replayed after the name expires
/// and is registered again. `seq` orders operations within one registration.
#[derive(Clone, Debug)]
pub enum SignedOp<'a> {
    Renew,
    Transfer { new_owner: &'a OwnerKey },
}

pub fn sighash(name: &Name, registered_at: u64, seq: u64, op: SignedOp<'_>) -> Hash256 {
    let mut buf = Vec::new();
    name.encode(&mut buf);
    buf.extend_from_slice(&registered_at.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    match op {
        SignedOp::Renew => buf.push(TAG_RENEW),
        SignedOp::Transfer { new_owner } => {
            buf.push(TAG_TRANSFER);
            buf.extend_from_slice(&new_owner.serialize());
        }
    }
    Hash256::tagged("namespace/sighash", &buf)
}

pub fn sign(keypair: &Keypair, digest: &Hash256) -> schnorr::Signature {
    Secp256k1::signing_only().sign_schnorr(&Message::from_digest(digest.0), keypair)
}

pub fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    key: &OwnerKey,
    digest: &Hash256,
    sig: &schnorr::Signature,
) -> bool {
    secp.verify_schnorr(sig, &Message::from_digest(digest.0), key)
        .is_ok()
}

impl Tx {
    pub fn txid(&self) -> Hash256 {
        Hash256::tagged("namespace/tx", &self.to_bytes())
    }

    pub fn name(&self) -> Option<&Name> {
        match self {
            Tx::Commit { .. } => None,
            Tx::Register { name, .. } | Tx::Renew { name, .. } | Tx::Transfer { name, .. } => {
                Some(name)
            }
        }
    }
}

fn decode_key(r: &mut Reader<'_>) -> Result<OwnerKey, DecodeError> {
    XOnlyPublicKey::from_slice(r.take(32)?).map_err(|_| DecodeError::Invalid("public key"))
}

fn decode_sig(r: &mut Reader<'_>) -> Result<schnorr::Signature, DecodeError> {
    schnorr::Signature::from_slice(r.take(64)?).map_err(|_| DecodeError::Invalid("signature"))
}

impl Encode for Tx {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Tx::Commit { commitment } => {
                out.push(TAG_COMMIT);
                commitment.encode(out);
            }
            Tx::Register { name, owner, salt } => {
                out.push(TAG_REGISTER);
                name.encode(out);
                out.extend_from_slice(&owner.serialize());
                salt.encode(out);
            }
            Tx::Renew { name, seq, sig } => {
                out.push(TAG_RENEW);
                name.encode(out);
                out.extend_from_slice(&seq.to_le_bytes());
                out.extend_from_slice(sig.as_ref());
            }
            Tx::Transfer {
                name,
                new_owner,
                seq,
                sig,
            } => {
                out.push(TAG_TRANSFER);
                name.encode(out);
                out.extend_from_slice(&new_owner.serialize());
                out.extend_from_slice(&seq.to_le_bytes());
                out.extend_from_slice(sig.as_ref());
            }
        }
    }
}

impl Decode for Tx {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.u8()? {
            TAG_COMMIT => Tx::Commit {
                commitment: Hash256::decode(r)?,
            },
            TAG_REGISTER => Tx::Register {
                name: Name::decode(r)?,
                owner: decode_key(r)?,
                salt: Hash256::decode(r)?,
            },
            TAG_RENEW => Tx::Renew {
                name: Name::decode(r)?,
                seq: r.u64()?,
                sig: decode_sig(r)?,
            },
            TAG_TRANSFER => Tx::Transfer {
                name: Name::decode(r)?,
                new_owner: decode_key(r)?,
                seq: r.u64()?,
                sig: decode_sig(r)?,
            },
            _ => return Err(DecodeError::Invalid("transaction tag")),
        })
    }
}
