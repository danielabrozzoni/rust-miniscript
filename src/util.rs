use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::{PubkeyHash, Script};

use crate::miniscript::context;
use crate::miniscript::satisfy::{PartialSatisfaction, Placeholder};
use crate::prelude::*;
use crate::{MiniscriptKey, ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize {
    bitcoin::VarInt(n as u64).len()
}

pub(crate) trait ItemSize {
    fn size(&self) -> usize;
}

impl<Pk: MiniscriptKey> ItemSize for Placeholder<Pk> {
    fn size(&self) -> usize {
        match self {
            Placeholder::PubkeyHash(_, size) => *size,
            Placeholder::Pubkey(_, size) => *size,
            Placeholder::EcdsaSigPk(_) | Placeholder::EcdsaSigHash(_) => 73,
            Placeholder::SchnorrSig(_, _) => 66,
            Placeholder::HashDissatisfaction
            | Placeholder::Sha256Preimage(_)
            | Placeholder::Hash256Preimage(_)
            | Placeholder::Ripemd160Preimage(_)
            | Placeholder::Hash160Preimage(_) => 33,
            Placeholder::PushOne => 2, // On legacy this should be 1 ?
            Placeholder::PushZero => 1,
            Placeholder::TapScript(s) => s.len(),
            Placeholder::TapControlBlock(cb) => cb.serialize().len(),
        }
    }
}

impl<Pk: MiniscriptKey> ItemSize for PartialSatisfaction<Pk> {
    fn size(&self) -> usize {
        match self {
            PartialSatisfaction::Placeholder(p) => p.size(),
            PartialSatisfaction::Data(d) => d.len() + varint_len(d.len()),
        }
    }
}

impl ItemSize for Vec<u8> {
    fn size(&self) -> usize {
        self.len()
    }
}

// Helper function to calculate witness size
pub(crate) fn witness_size<T: ItemSize>(wit: &[T]) -> usize {
    wit.iter().map(T::size).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
    let mut b = script::Builder::new();
    for wit in witness {
        if let Ok(n) = script::read_scriptint(wit) {
            b = b.push_int(n);
        } else {
            b = b.push_slice(wit);
        }
    }
    b.into_script()
}

// trait for pushing key that depend on context
pub(crate) trait MsKeyBuilder {
    /// Serialize the key as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;

    /// Serialize the key hash as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;
}

impl MsKeyBuilder for script::Builder {
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_key(&key.to_public_key()),
            context::SigType::Schnorr => self.push_slice(&key.to_x_only_pubkey().serialize()),
        }
    }

    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_slice(&key.to_public_key().pubkey_hash()),
            context::SigType::Schnorr => {
                self.push_slice(&PubkeyHash::hash(&key.to_x_only_pubkey().serialize()))
            }
        }
    }
}
