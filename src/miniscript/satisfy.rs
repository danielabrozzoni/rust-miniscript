// Miniscript
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Satisfaction and Dissatisfaction
//!
//! Traits and implementations to support producing witnesses for Miniscript
//! scriptpubkeys.
//!

use core::{cmp, i64, mem};
use std::fmt;

use bitcoin::hashes::hash160;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{LockTime, PackedLockTime, Script, Sequence};
use sync::Arc;

use super::context::SigType;
use crate::descriptor::DescriptorType;
use crate::plan::{AssetProvider, Plan};
use crate::prelude::*;
use crate::util::witness_size;
use crate::{
    DefiniteDescriptorKey, Miniscript, MiniscriptKey, ScriptContext, Terminal, ToPublicKey,
};

/// Type alias for 32 byte Preimage.
pub type Preimage32 = [u8; 32];
/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk: MiniscriptKey + ToPublicKey> {
    /// Given a public key, look up an ECDSA signature with that key
    fn lookup_ecdsa_sig(&self, _: &Pk) -> Option<bitcoin::EcdsaSig> {
        None
    }

    /// Lookup the tap key spend sig
    fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::SchnorrSig> {
        None
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
        None
    }

    /// Obtain a reference to the control block for a ver and script
    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (bitcoin::Script, LeafVersion)>> {
        None
    }

    /// Given a raw `Pkh`, lookup corresponding `Pk`
    fn lookup_raw_pkh_pk(&self, _: &hash160::Hash) -> Option<Pk> {
        None
    }

    /// Given a keyhash, look up the EC signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        _: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::EcdsaSig)> {
        None
    }

    /// Given a keyhash, look up the schnorr signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        _: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, bitcoin::SchnorrSig)> {
        None
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: &Pk::Sha256) -> Option<Preimage32> {
        None
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: &Pk::Hash256) -> Option<Preimage32> {
        None
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: &Pk::Ripemd160) -> Option<Preimage32> {
        None
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: &Pk::Hash160) -> Option<Preimage32> {
        None
    }

    /// Assert whether an relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether a absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }
}

// Allow use of `()` as a "no conditions available" satisfier
impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for () {}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for Sequence {
    fn check_older(&self, n: Sequence) -> bool {
        if !self.is_relative_lock_time() {
            return false;
        }

        // We need a relative lock time type in rust-bitcoin to clean this up.

        /* If nSequence encodes a relative lock-time, this mask is
         * applied to extract that lock-time from the sequence field. */
        const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
        const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 0x00400000;

        let mask = SEQUENCE_LOCKTIME_MASK | SEQUENCE_LOCKTIME_TYPE_FLAG;
        let masked_n = n.to_consensus_u32() & mask;
        let masked_seq = self.to_consensus_u32() & mask;
        if masked_n < SEQUENCE_LOCKTIME_TYPE_FLAG && masked_seq >= SEQUENCE_LOCKTIME_TYPE_FLAG {
            false
        } else {
            masked_n <= masked_seq
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for LockTime {
    fn check_after(&self, n: LockTime) -> bool {
        use LockTime::*;

        match (n, *self) {
            (Blocks(n), Blocks(lock_time)) => n <= lock_time,
            (Seconds(n), Seconds(lock_time)) => n <= lock_time,
            _ => false, // Not the same units.
        }
    }
}
impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<Pk, bitcoin::EcdsaSig> {
    fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<bitcoin::EcdsaSig> {
        self.get(key).copied()
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk>
    for HashMap<(Pk, TapLeafHash), bitcoin::SchnorrSig>
{
    fn lookup_tap_leaf_script_sig(&self, key: &Pk, h: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
        // Unfortunately, there is no way to get a &(a, b) from &a and &b without allocating
        // If we change the signature the of lookup_tap_leaf_script_sig to accept a tuple. We would
        // face the same problem while satisfying PkK.
        // We use this signature to optimize for the psbt common use case.
        self.get(&(key.clone(), *h)).copied()
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk>
    for HashMap<hash160::Hash, (Pk, bitcoin::EcdsaSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<bitcoin::EcdsaSig> {
        self.get(&key.to_pubkeyhash(SigType::Ecdsa)).map(|x| x.1)
    }

    fn lookup_raw_pkh_pk(&self, pk_hash: &hash160::Hash) -> Option<Pk> {
        self.get(pk_hash).map(|x| x.0.clone())
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pk_hash: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::EcdsaSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_public_key(), sig))
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk>
    for HashMap<(hash160::Hash, TapLeafHash), (Pk, bitcoin::SchnorrSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_tap_leaf_script_sig(&self, key: &Pk, h: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
        self.get(&(key.to_pubkeyhash(SigType::Schnorr), *h))
            .map(|x| x.1)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pk_hash: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, bitcoin::SchnorrSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_x_only_pubkey(), sig))
    }
}

impl<'a, Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a S {
    fn lookup_ecdsa_sig(&self, p: &Pk) -> Option<bitcoin::EcdsaSig> {
        (**self).lookup_ecdsa_sig(p)
    }

    fn lookup_tap_leaf_script_sig(&self, p: &Pk, h: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
        (**self).lookup_tap_leaf_script_sig(p, h)
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<Pk> {
        (**self).lookup_raw_pkh_pk(pkh)
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::EcdsaSig)> {
        (**self).lookup_raw_pkh_ecdsa_sig(pkh)
    }

    fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::SchnorrSig> {
        (**self).lookup_tap_key_spend_sig()
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, bitcoin::SchnorrSig)> {
        (**self).lookup_raw_pkh_tap_leaf_script_sig(pkh)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (bitcoin::Script, LeafVersion)>> {
        (**self).lookup_tap_control_block_map()
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: Sequence) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, n: LockTime) -> bool {
        (**self).check_after(n)
    }
}

impl<'a, Pk: MiniscriptKey + ToPublicKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a mut S {
    fn lookup_ecdsa_sig(&self, p: &Pk) -> Option<bitcoin::EcdsaSig> {
        (**self).lookup_ecdsa_sig(p)
    }

    fn lookup_tap_leaf_script_sig(&self, p: &Pk, h: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
        (**self).lookup_tap_leaf_script_sig(p, h)
    }

    fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::SchnorrSig> {
        (**self).lookup_tap_key_spend_sig()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<Pk> {
        (**self).lookup_raw_pkh_pk(pkh)
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, bitcoin::EcdsaSig)> {
        (**self).lookup_raw_pkh_ecdsa_sig(pkh)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, bitcoin::SchnorrSig)> {
        (**self).lookup_raw_pkh_tap_leaf_script_sig(pkh)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (bitcoin::Script, LeafVersion)>> {
        (**self).lookup_tap_control_block_map()
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: Sequence) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, n: LockTime) -> bool {
        (**self).check_after(n)
    }
}

macro_rules! impl_tuple_satisfier {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* Pk> Satisfier<Pk> for ($($ty,)*)
        where
            Pk: MiniscriptKey + ToPublicKey,
            $($ty: Satisfier< Pk>,)*
        {
            fn lookup_ecdsa_sig(&self, key: &Pk) -> Option<bitcoin::EcdsaSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ecdsa_sig(key) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_key_spend_sig(&self) -> Option<bitcoin::SchnorrSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_key_spend_sig() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_leaf_script_sig(&self, key: &Pk, h: &TapLeafHash) -> Option<bitcoin::SchnorrSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_leaf_script_sig(key, h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_ecdsa_sig(
                &self,
                key_hash: &hash160::Hash,
            ) -> Option<(bitcoin::PublicKey, bitcoin::EcdsaSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_ecdsa_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_tap_leaf_script_sig(
                &self,
                key_hash: &(hash160::Hash, TapLeafHash),
            ) -> Option<(XOnlyPublicKey, bitcoin::SchnorrSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_tap_leaf_script_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_raw_pkh_pk(
                &self,
                key_hash: &hash160::Hash,
            ) -> Option<Pk> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_raw_pkh_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_tap_control_block_map(
                &self,
            ) -> Option<&BTreeMap<ControlBlock, (bitcoin::Script, LeafVersion)>> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_tap_control_block_map() {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sha256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ripemd160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn check_older(&self, n: Sequence) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_older(n) {
                        return true;
                    }
                )*
                false
            }

            fn check_after(&self, n: LockTime) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_after(n) {
                        return true;
                    }
                )*
                false
            }
        }
    }
}

impl_tuple_satisfier!(A);
impl_tuple_satisfier!(A, B);
impl_tuple_satisfier!(A, B, C);
impl_tuple_satisfier!(A, B, C, D);
impl_tuple_satisfier!(A, B, C, D, E);
impl_tuple_satisfier!(A, B, C, D, E, F);
impl_tuple_satisfier!(A, B, C, D, E, F, G);
impl_tuple_satisfier!(A, B, C, D, E, F, G, H);

#[derive(Debug, Clone, PartialEq, Eq)]
/// Placeholder for some data in a [`WitnessTemplate`]
pub enum Placeholder<Pk: MiniscriptKey> {
    /// Public key and its size
    Pubkey(Pk, usize),
    /// Public key hash and its size
    PubkeyHash(hash160::Hash, usize),
    /// ECDSA signature given the raw pubkey
    EcdsaSigPk(Pk),
    /// ECDSA signature given the pubkey hash
    EcdsaSigHash(hash160::Hash),
    /// Schnorr signature
    SchnorrSig(Pk, Option<TapLeafHash>),
    /// SHA-256 preimage
    Sha256Preimage(Pk::Sha256),
    /// HASH256 preimage
    Hash256Preimage(Pk::Hash256),
    /// RIPEMD160 preimage
    Ripemd160Preimage(Pk::Ripemd160),
    /// HASH160 preimage
    Hash160Preimage(Pk::Hash160),
    /// Hash dissatisfaction (32 bytes of 0x00)
    HashDissatisfaction,
    /// OP_1
    PushOne,
    /// <empty item>
    PushZero,

    /// Taproot leaf script
    TapScript(Script),
    /// Taproot control block
    TapControlBlock(ControlBlock),
}

impl<Pk: MiniscriptKey> fmt::Display for Placeholder<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use bitcoin::hashes::hex::ToHex;
        use Placeholder::*;
        match self {
            Pubkey(pk, size) => write!(f, "Pubkey(pk: {}, size: {})", pk, size),
            PubkeyHash(pkh, size) => write!(f, "PubkeyHash(pkh: {}, size: {})", pkh, size),
            EcdsaSigPk(pk) => write!(f, "EcdsaSigPk(pk: {})", pk),
            EcdsaSigHash(hash) => write!(f, "EcdsaSigHash(hash: {})", hash),
            SchnorrSig(pk, tap_leaf_hash) => write!(
                f,
                "SchnorrSig(pk: {}, tap_leaf_hash: {:?})",
                pk, tap_leaf_hash
            ),
            Sha256Preimage(hash) => write!(f, "Sha256Preimage(hash: {})", hash),
            Hash256Preimage(hash) => write!(f, "Hash256Preimage(hash: {})", hash),
            Ripemd160Preimage(hash) => write!(f, "Ripemd160Preimage(hash: {})", hash),
            Hash160Preimage(hash) => write!(f, "Hash160Preimage(hash: {})", hash),
            HashDissatisfaction => write!(f, "HashDissatisfaction"),
            PushOne => write!(f, "PushOne"),
            PushZero => write!(f, "PushZero"),
            TapScript(script) => write!(f, "TapScript(script: {})", script),
            TapControlBlock(control_block) => write!(
                f,
                "TapControlBlock(control_block: {})",
                control_block.serialize().to_hex()
            ),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Placeholder<Pk> {
    /// Replaces the placeholders with the information given by the satisfier
    fn satisfy_self<Sat: Satisfier<Pk>>(&self, sat: &Sat) -> Option<Vec<u8>> {
        match self {
            Placeholder::Pubkey(pk, _) => Some(pk.to_public_key().to_bytes()),
            // Placeholder::PubkeyHash might be created after a call to lookup_raw_pkh_pk (in
            // pkh_public_key) or a call to lookup_raw_pkh_ecdsa_sig (in pkh_signature).
            // For this reason, here we have to call both methods to find the key.
            Placeholder::PubkeyHash(pkh, size) => sat
                .lookup_raw_pkh_pk(pkh)
                .map(|p| p.to_public_key())
                .or(sat.lookup_raw_pkh_ecdsa_sig(pkh).map(|(p, _)| p))
                .map(|pk| {
                    let pk = pk.to_bytes();
                    // We have to add a 1-byte OP_PUSH
                    debug_assert!(1 + pk.len() == *size);
                    pk
                }),
            Placeholder::Hash256Preimage(h) => sat.lookup_hash256(h).map(|p| p.to_vec()),
            Placeholder::Sha256Preimage(h) => sat.lookup_sha256(h).map(|p| p.to_vec()),
            Placeholder::Hash160Preimage(h) => sat.lookup_hash160(h).map(|p| p.to_vec()),
            Placeholder::Ripemd160Preimage(h) => sat.lookup_ripemd160(h).map(|p| p.to_vec()),
            Placeholder::EcdsaSigPk(pk) => sat.lookup_ecdsa_sig(pk).map(|s| s.to_vec()),
            Placeholder::EcdsaSigHash(pkh) => {
                sat.lookup_raw_pkh_ecdsa_sig(pkh).map(|(_, s)| s.to_vec())
            }
            Placeholder::SchnorrSig(pk, Some(leaf_hash)) => sat
                .lookup_tap_leaf_script_sig(pk, leaf_hash)
                .map(|s| s.to_vec()),
            Placeholder::SchnorrSig(_, _) => sat.lookup_tap_key_spend_sig().map(|s| s.to_vec()),
            Placeholder::HashDissatisfaction => Some(vec![0; 32]),
            Placeholder::PushZero => Some(vec![]),
            Placeholder::PushOne => Some(vec![1]),
            Placeholder::TapScript(s) => Some(s.to_bytes()),
            Placeholder::TapControlBlock(cb) => Some(cb.serialize()),
        }
    }
}

/// A witness, if available, for a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Witness<T> {
    /// Witness Available and the value of the witness
    Stack(Vec<T>),
    /// Third party can possibly satisfy the fragment but we cannot
    /// Witness Unavailable
    Unavailable,
    /// No third party can produce a satisfaction without private key
    /// Witness Impossible
    Impossible,
}

/// Enum for partially satisfied witness templates
pub enum PartialSatisfaction<Pk: MiniscriptKey> {
    /// Placeholder item (not yet satisfied)
    Placeholder(Placeholder<Pk>),
    /// Actual data
    Data(Vec<u8>),
}

impl<Pk: MiniscriptKey> PartialSatisfaction<Pk> {
    /// Whether the item is a placeholder
    pub fn is_placeholder(&self) -> bool {
        match &self {
            PartialSatisfaction::Placeholder(_) => true,
            _ => false,
        }
    }

    /// Whether the item is data
    pub fn is_data(&self) -> bool {
        !self.is_placeholder()
    }
}

/// Template of a witness being constructed interactively
///
/// The generic `I` type determines the available API:
/// - `Placeholder<Pk>` indicates the witness only contains placeholders, i.e. it's just an empty
///   template
/// - `PartialSatisfaction<Pk>` indicates the witness contains some placeholders and some actual
///   pieces of data
#[derive(Debug, Clone)]
pub struct WitnessTemplate<I> {
    stack: Vec<I>,
}

impl<I> AsRef<[I]> for WitnessTemplate<I> {
    fn as_ref(&self) -> &[I] {
        &self.stack
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> WitnessTemplate<Placeholder<Pk>> {
    /// Construct an instance from a stack of placeholders
    pub fn from_placeholder_stack(stack: Vec<Placeholder<Pk>>) -> Self {
        WitnessTemplate { stack }
    }

    /// Try completing the witness in one go using a [`Satisfier`]
    pub fn try_completing<Sat: Satisfier<Pk>>(&self, stfr: &Sat) -> Option<Vec<Vec<u8>>> {
        let stack = self
            .stack
            .iter()
            .map(|placeholder| placeholder.satisfy_self(stfr))
            .collect::<Option<_>>()?;

        Some(stack)
    }

    /// Being an interactive satisfaction session
    pub fn interactive_satisfaction(self) -> WitnessTemplate<PartialSatisfaction<Pk>> {
        WitnessTemplate {
            stack: self
                .stack
                .into_iter()
                .map(PartialSatisfaction::Placeholder)
                .collect(),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> WitnessTemplate<PartialSatisfaction<Pk>> {
    /// Apply the items needed from a satisfier
    ///
    /// Returns the completed witness if all the placeholders have been filled, or `Err` with itself a list of missing
    /// items otherwise.
    pub fn apply<Sat: Satisfier<Pk>>(
        self,
        stfr: &Sat,
    ) -> Result<Vec<Vec<u8>>, (Self, Vec<Placeholder<Pk>>)> {
        let mut unsatisfied = vec![];

        let stack = self
            .stack
            .into_iter()
            .map(|ps| {
                let placeholder = match &ps {
                    PartialSatisfaction::Placeholder(p) => p,
                    PartialSatisfaction::Data(_) => return ps,
                };

                if let Some(data) = placeholder.satisfy_self(stfr) {
                    return PartialSatisfaction::Data(data);
                }

                unsatisfied.push(placeholder.clone());
                ps
            })
            .collect::<Vec<_>>();

        if unsatisfied.is_empty() {
            Ok(stack
                .into_iter()
                .map(|ps| match ps {
                    PartialSatisfaction::Data(d) => d,
                    PartialSatisfaction::Placeholder(_) => {
                        unreachable!("there shouldn't be any placeholder left")
                    }
                })
                .collect())
        } else {
            Err((WitnessTemplate { stack }, unsatisfied))
        }
    }
}

impl<Pk: MiniscriptKey> PartialOrd for Witness<Placeholder<Pk>> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Pk: MiniscriptKey> Ord for Witness<Placeholder<Pk>> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (&Witness::Stack(ref v1), &Witness::Stack(ref v2)) => {
                let w1 = witness_size(v1);
                let w2 = witness_size(v2);
                w1.cmp(&w2)
            }
            (&Witness::Stack(_), _) => cmp::Ordering::Less,
            (_, &Witness::Stack(_)) => cmp::Ordering::Greater,
            (&Witness::Impossible, &Witness::Unavailable) => cmp::Ordering::Less,
            (&Witness::Unavailable, &Witness::Impossible) => cmp::Ordering::Greater,
            (&Witness::Impossible, &Witness::Impossible) => cmp::Ordering::Equal,
            (&Witness::Unavailable, &Witness::Unavailable) => cmp::Ordering::Equal,
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Witness<Placeholder<Pk>> {
    /// Turn a signature into (part of) a satisfaction
    fn signature<S: AssetProvider<Pk>, Ctx: ScriptContext>(
        sat: &S,
        pk: &Pk,
        leaf_hash: &TapLeafHash,
    ) -> Self {
        match Ctx::sig_type() {
            super::context::SigType::Ecdsa => {
                if sat.lookup_ecdsa_sig(pk) {
                    Witness::Stack(vec![Placeholder::EcdsaSigPk(pk.clone())])
                } else {
                    // Signatures cannot be forged
                    Witness::Impossible
                }
            }
            super::context::SigType::Schnorr => {
                if sat.lookup_tap_leaf_script_sig(pk, leaf_hash) {
                    Witness::Stack(vec![Placeholder::SchnorrSig(
                        pk.clone(),
                        Some(leaf_hash.clone()),
                    )])
                } else {
                    // Signatures cannot be forged
                    Witness::Impossible
                }
            }
        }
    }

    /// Turn a public key related to a pkh into (part of) a satisfaction
    fn pkh_public_key<S: AssetProvider<Pk>, Ctx: ScriptContext>(
        sat: &S,
        pkh: &hash160::Hash,
    ) -> Self {
        if let Some(pk_len) = sat.lookup_raw_pkh_pk::<Ctx>(pkh) {
            Witness::Stack(vec![Placeholder::PubkeyHash(pkh.clone(), pk_len)])
        } else {
            // public key hashes are assumed to be unavailable
            // instead of impossible since it is the same as pub-key hashes
            Witness::Unavailable
        }
    }

    /// Turn a key/signature pair related to a pkh into (part of) a satisfaction
    fn pkh_signature<S: AssetProvider<Pk>, Ctx: ScriptContext>(
        sat: &S,
        pkh: &hash160::Hash,
    ) -> Self {
        if let Some(pk_len) = sat.lookup_raw_pkh_ecdsa_sig::<Ctx>(pkh) {
            Witness::Stack(vec![
                Placeholder::EcdsaSigHash(pkh.clone()),
                Placeholder::PubkeyHash(pkh.clone(), pk_len),
            ])
        } else {
            Witness::Impossible
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn ripemd160_preimage<S: AssetProvider<Pk>>(sat: &S, h: &Pk::Ripemd160) -> Self {
        if sat.lookup_ripemd160(h) {
            Witness::Stack(vec![Placeholder::Ripemd160Preimage(h.clone())])
        // Note hash preimages are unavailable instead of impossible
        } else {
            Witness::Unavailable
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash160_preimage<S: AssetProvider<Pk>>(sat: &S, h: &Pk::Hash160) -> Self {
        if sat.lookup_hash160(h) {
            Witness::Stack(vec![Placeholder::Hash160Preimage(h.clone())])
        // Note hash preimages are unavailable instead of impossible
        } else {
            Witness::Unavailable
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn sha256_preimage<S: AssetProvider<Pk>>(sat: &S, h: &Pk::Sha256) -> Self {
        if sat.lookup_sha256(h) {
            Witness::Stack(vec![Placeholder::Sha256Preimage(h.clone())])
        // Note hash preimages are unavailable instead of impossible
        } else {
            Witness::Unavailable
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash256_preimage<S: AssetProvider<Pk>>(sat: &S, h: &Pk::Hash256) -> Self {
        if sat.lookup_hash256(h) {
            Witness::Stack(vec![Placeholder::Hash256Preimage(h.clone())])
        // Note hash preimages are unavailable instead of impossible
        } else {
            Witness::Unavailable
        }
    }
}

impl<Pk: MiniscriptKey> Witness<Placeholder<Pk>> {
    /// Produce something like a 32-byte 0 push
    fn hash_dissatisfaction() -> Self {
        Witness::Stack(vec![Placeholder::HashDissatisfaction])
    }

    /// Construct a satisfaction equivalent to an empty stack
    fn empty() -> Self {
        Witness::Stack(vec![])
    }

    /// Construct a satisfaction equivalent to `OP_1`
    fn push_1() -> Self {
        Witness::Stack(vec![Placeholder::PushOne])
    }

    /// Construct a satisfaction equivalent to a single empty push
    fn push_0() -> Self {
        Witness::Stack(vec![Placeholder::PushZero])
    }

    /// Concatenate, or otherwise combine, two satisfactions
    fn combine(one: Self, two: Self) -> Self {
        match (one, two) {
            (Witness::Impossible, _) | (_, Witness::Impossible) => Witness::Impossible,
            (Witness::Unavailable, _) | (_, Witness::Unavailable) => Witness::Unavailable,
            (Witness::Stack(mut a), Witness::Stack(b)) => {
                a.extend(b);
                Witness::Stack(a)
            }
        }
    }
}

/// A (dis)satisfaction of a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Satisfaction<T> {
    /// The actual witness stack
    pub stack: Witness<T>,
    /// Whether or not this (dis)satisfaction has a signature somewhere
    /// in it
    pub has_sig: bool,
    // We use PackedLockTime here as we need to compare timelocks using Ord. This is safe,
    // as miniscript checks for us beforehand that the timelocks are of the same type.
    /// The absolute timelock used by this satisfaction
    pub absolute_timelock: Option<PackedLockTime>,
    /// The relative timelock used by this satisfaction
    pub relative_timelock: Option<Sequence>,
}

impl<T> Satisfaction<T> {
    pub(crate) fn map_stack<U, F>(self, mapfn: F) -> Satisfaction<U>
    where
        F: Fn(Vec<T>) -> Vec<U>,
    {
        let Satisfaction {
            stack,
            has_sig,
            relative_timelock,
            absolute_timelock,
        } = self;
        let stack = match stack {
            Witness::Stack(stack) => Witness::Stack(mapfn(stack)),
            Witness::Unavailable => Witness::Unavailable,
            Witness::Impossible => Witness::Impossible,
        };
        Satisfaction {
            stack,
            has_sig,
            relative_timelock,
            absolute_timelock,
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfaction<Placeholder<Pk>> {
    pub(crate) fn build_template<P, Ctx>(
        term: &Terminal<Pk, Ctx>,
        provider: &P,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        Ctx: ScriptContext,
        P: AssetProvider<Pk>,
    {
        Self::satisfy_helper(
            term,
            provider,
            root_has_sig,
            leaf_hash,
            &mut Satisfaction::minimum,
            &mut Satisfaction::thresh,
        )
    }

    pub(crate) fn build_template_mall<P, Ctx>(
        term: &Terminal<Pk, Ctx>,
        provider: &P,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        Ctx: ScriptContext,
        P: AssetProvider<Pk>,
    {
        Self::satisfy_helper(
            term,
            provider,
            root_has_sig,
            leaf_hash,
            &mut Satisfaction::minimum_mall,
            &mut Satisfaction::thresh_mall,
        )
    }

    // produce a non-malleable satisafaction for thesh frag
    fn thresh<Ctx, Sat, F>(
        k: usize,
        subs: &[Arc<Miniscript<Pk, Ctx>>],
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
    ) -> Self
    where
        Ctx: ScriptContext,
        Sat: AssetProvider<Pk>,
        F: FnMut(
            Satisfaction<Placeholder<Pk>>,
            Satisfaction<Placeholder<Pk>>,
        ) -> Satisfaction<Placeholder<Pk>>,
    {
        let mut sats = subs
            .iter()
            .map(|s| {
                Self::satisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh,
                )
            })
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh,
                )
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
                // This can only be the case when we have PkH without the corresponding
                // Pubkey.
                (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
                (&Witness::Stack(ref s), &Witness::Stack(ref d)) => {
                    witness_size(s) as i64 - witness_size(d) as i64
                }
            };
            let is_impossible = sats[i].stack == Witness::Impossible;
            // First consider the candidates that are not impossible to satisfy
            // by any party. Among those first consider the ones that have no sig
            // because third party can malleate them if they are not chosen.
            // Lastly, choose by weight.
            (is_impossible, sats[i].has_sig, stack_weight)
        });

        for i in 0..k {
            mem::swap(&mut ret_stack[sat_indices[i]], &mut sats[sat_indices[i]]);
        }

        // We preferably take satisfactions that are not impossible
        // If we cannot find `k` satisfactions that are not impossible
        // then the threshold branch is impossible to satisfy
        // For example, the fragment thresh(2, hash, 0, 0, 0)
        // is has an impossible witness
        assert!(k > 0);
        if sats[sat_indices[k - 1]].stack == Witness::Impossible {
            Satisfaction {
                stack: Witness::Impossible,
                // If the witness is impossible, we don't care about the
                // has_sig flag, nor about the timelocks
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            }
        }
        // We are now guaranteed that all elements in `k` satisfactions
        // are not impossible(we sort by is_impossible bool).
        // The above loop should have taken everything without a sig
        // (since those were sorted higher than non-sigs). If there
        // are remaining non-sig satisfactions this indicates a
        // malleability vector
        // For example, the fragment thresh(2, hash, hash, 0, 0)
        // is uniquely satisfyiable because there is no satisfaction
        // for the 0 fragment
        else if k < sat_indices.len()
            && !sats[sat_indices[k]].has_sig
            && sats[sat_indices[k]].stack != Witness::Impossible
        {
            // All arguments should be `d`, so dissatisfactions have no
            // signatures; and in this branch we assume too many weak
            // arguments, so none of the satisfactions should have
            // signatures either.
            for sat in &ret_stack {
                assert!(!sat.has_sig);
            }
            Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            }
        } else {
            // Otherwise flatten everything out
            Satisfaction {
                has_sig: ret_stack.iter().any(|sat| sat.has_sig),
                relative_timelock: ret_stack
                    .iter()
                    .filter_map(|sat| sat.relative_timelock)
                    .max(),
                absolute_timelock: ret_stack
                    .iter()
                    .filter_map(|sat| sat.absolute_timelock)
                    .max(),
                stack: ret_stack.into_iter().fold(Witness::empty(), |acc, next| {
                    Witness::combine(next.stack, acc)
                }),
            }
        }
    }

    // produce a possily malleable satisafaction for thesh frag
    fn thresh_mall<Ctx, Sat, F>(
        k: usize,
        subs: &[Arc<Miniscript<Pk, Ctx>>],
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
    ) -> Self
    where
        Ctx: ScriptContext,
        Sat: AssetProvider<Pk>,
        F: FnMut(
            Satisfaction<Placeholder<Pk>>,
            Satisfaction<Placeholder<Pk>>,
        ) -> Satisfaction<Placeholder<Pk>>,
    {
        let mut sats = subs
            .iter()
            .map(|s| {
                Self::satisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh_mall,
                )
            })
            .collect::<Vec<_>>();
        // Start with the to-return stack set to all dissatisfactions
        let mut ret_stack = subs
            .iter()
            .map(|s| {
                Self::dissatisfy_helper(
                    &s.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    &mut Self::thresh_mall,
                )
            })
            .collect::<Vec<_>>();

        // Sort everything by (sat cost - dissat cost), except that
        // satisfactions without signatures beat satisfactions with
        // signatures
        let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
        sat_indices.sort_by_key(|&i| {
            // For malleable satifactions, directly choose smallest weights
            match (&sats[i].stack, &ret_stack[i].stack) {
                (&Witness::Unavailable, _) | (&Witness::Impossible, _) => i64::MAX,
                // This is only possible when one of the branches has PkH
                (_, &Witness::Unavailable) | (_, &Witness::Impossible) => i64::MIN,
                (&Witness::Stack(ref s), &Witness::Stack(ref d)) => {
                    witness_size(s) as i64 - witness_size(d) as i64
                }
            }
        });

        // swap the satisfactions
        for i in 0..k {
            mem::swap(&mut ret_stack[sat_indices[i]], &mut sats[sat_indices[i]]);
        }

        // combine the witness
        // no non-malleability checks needed
        Satisfaction {
            has_sig: ret_stack.iter().any(|sat| sat.has_sig),
            relative_timelock: ret_stack
                .iter()
                .filter_map(|sat| sat.relative_timelock)
                .max(),
            absolute_timelock: ret_stack
                .iter()
                .filter_map(|sat| sat.absolute_timelock)
                .max(),
            stack: ret_stack.into_iter().fold(Witness::empty(), |acc, next| {
                Witness::combine(next.stack, acc)
            }),
        }
    }

    fn minimum(sat1: Self, sat2: Self) -> Self {
        // If there is only one available satisfaction, we must choose that
        // regardless of has_sig marker.
        // This handles the case where both are impossible.
        match (&sat1.stack, &sat2.stack) {
            (&Witness::Impossible, _) => return sat2,
            (_, &Witness::Impossible) => return sat1,
            _ => {}
        }
        match (sat1.has_sig, sat2.has_sig) {
            // If neither option has a signature, this is a malleability
            // vector, so choose neither one.
            (false, false) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            // If only one has a signature, take the one that doesn't; a
            // third party could malleate by removing the signature, but
            // can't malleate if he'd have to add it
            (false, true) => Satisfaction {
                stack: sat1.stack,
                has_sig: false,
                relative_timelock: sat1.relative_timelock,
                absolute_timelock: sat1.absolute_timelock,
            },
            (true, false) => Satisfaction {
                stack: sat2.stack,
                has_sig: false,
                relative_timelock: sat2.relative_timelock,
                absolute_timelock: sat2.absolute_timelock,
            },
            // If both have a signature associated with them, choose the
            // cheaper one (where "cheaper" is defined such that available
            // things are cheaper than unavailable ones)
            (true, true) if sat1.stack < sat2.stack => Satisfaction {
                stack: sat1.stack,
                has_sig: true,
                relative_timelock: sat1.relative_timelock,
                absolute_timelock: sat1.absolute_timelock,
            },
            (true, true) => Satisfaction {
                stack: sat2.stack,
                has_sig: true,
                relative_timelock: sat2.relative_timelock,
                absolute_timelock: sat2.absolute_timelock,
            },
        }
    }

    // calculate the minimum witness allowing witness malleability
    fn minimum_mall(sat1: Self, sat2: Self) -> Self {
        match (&sat1.stack, &sat2.stack) {
            // If there is only one possible satisfaction, use it regardless
            // of the other one
            (&Witness::Impossible, _) | (&Witness::Unavailable, _) => return sat2,
            (_, &Witness::Impossible) | (_, &Witness::Unavailable) => return sat1,
            _ => {}
        }
        let (stack, absolute_timelock, relative_timelock) = if sat1.stack < sat2.stack {
            (sat1.stack, sat1.absolute_timelock, sat1.relative_timelock)
        } else {
            (sat2.stack, sat2.absolute_timelock, sat2.relative_timelock)
        };
        Satisfaction {
            stack,
            // The fragment is has_sig only if both of the
            // fragments are has_sig
            has_sig: sat1.has_sig && sat2.has_sig,
            relative_timelock,
            absolute_timelock,
        }
    }

    // produce a non-malleable satisfaction
    fn satisfy_helper<Ctx, Sat, F, G>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Ctx: ScriptContext,
        Sat: AssetProvider<Pk>,
        F: FnMut(
            Satisfaction<Placeholder<Pk>>,
            Satisfaction<Placeholder<Pk>>,
        ) -> Satisfaction<Placeholder<Pk>>,
        G: FnMut(
            usize,
            &[Arc<Miniscript<Pk, Ctx>>],
            &Sat,
            bool,
            &TapLeafHash,
            &mut F,
        ) -> Satisfaction<Placeholder<Pk>>,
    {
        match *term {
            Terminal::PkK(ref pk) => Satisfaction {
                stack: Witness::signature::<_, Ctx>(stfr, pk, leaf_hash),
                has_sig: true,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::PkH(ref pk) => Satisfaction {
                stack: Witness::pkh_signature::<_, Ctx>(stfr, &pk.to_pubkeyhash(Ctx::sig_type())),
                has_sig: true,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::RawPkH(ref pkh) => Satisfaction {
                stack: Witness::pkh_signature::<_, Ctx>(stfr, pkh),
                has_sig: true,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::After(t) => {
                let (stack, absolute_timelock) = if stfr.check_after(t.into()) {
                    (Witness::empty(), Some(t))
                } else if root_has_sig {
                    // If the root terminal has signature, the
                    // signature covers the nLockTime and nSequence
                    // values. The sender of the transaction should
                    // take care that it signs the value such that the
                    // timelock is not met
                    (Witness::Impossible, None)
                } else {
                    (Witness::Unavailable, None)
                };
                Satisfaction {
                    stack,
                    has_sig: false,
                    relative_timelock: None,
                    absolute_timelock,
                }
            }
            Terminal::Older(t) => {
                let (stack, relative_timelock) = if stfr.check_older(t) {
                    (Witness::empty(), Some(t))
                } else if root_has_sig {
                    // If the root terminal has signature, the
                    // signature covers the nLockTime and nSequence
                    // values. The sender of the transaction should
                    // take care that it signs the value such that the
                    // timelock is not met
                    (Witness::Impossible, None)
                } else {
                    (Witness::Unavailable, None)
                };
                Satisfaction {
                    stack,
                    has_sig: false,
                    relative_timelock,
                    absolute_timelock: None,
                }
            }
            Terminal::Ripemd160(ref h) => Satisfaction {
                stack: Witness::ripemd160_preimage(stfr, h),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Hash160(ref h) => Satisfaction {
                stack: Witness::hash160_preimage(stfr, h),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Sha256(ref h) => Satisfaction {
                stack: Witness::sha256_preimage(stfr, h),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Hash256(ref h) => Satisfaction {
                stack: Witness::hash256_preimage(stfr, h),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::True => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::False => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::satisfy_helper(&sub.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn)
            }
            Terminal::DupIf(ref sub) => {
                let sat = Self::satisfy_helper(
                    &sub.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(sat.stack, Witness::push_1()),
                    has_sig: sat.has_sig,
                    relative_timelock: sat.relative_timelock,
                    absolute_timelock: sat.absolute_timelock,
                }
            }
            Terminal::AndV(ref l, ref r) | Terminal::AndB(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                Satisfaction {
                    stack: Witness::combine(r_sat.stack, l_sat.stack),
                    has_sig: l_sat.has_sig || r_sat.has_sig,
                    relative_timelock: std::cmp::max(
                        l_sat.relative_timelock,
                        r_sat.relative_timelock,
                    ),
                    absolute_timelock: std::cmp::max(
                        l_sat.absolute_timelock,
                        r_sat.absolute_timelock,
                    ),
                }
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let a_sat =
                    Self::satisfy_helper(&a.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let a_nsat = Self::dissatisfy_helper(
                    &a.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let b_sat =
                    Self::satisfy_helper(&b.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let c_sat =
                    Self::satisfy_helper(&c.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);

                min_fn(
                    Satisfaction {
                        stack: Witness::combine(b_sat.stack, a_sat.stack),
                        has_sig: a_sat.has_sig || b_sat.has_sig,
                        relative_timelock: std::cmp::max(
                            a_sat.relative_timelock,
                            b_sat.relative_timelock,
                        ),
                        absolute_timelock: std::cmp::max(
                            a_sat.absolute_timelock,
                            b_sat.absolute_timelock,
                        ),
                    },
                    Satisfaction {
                        stack: Witness::combine(c_sat.stack, a_nsat.stack),
                        has_sig: a_nsat.has_sig || c_sat.has_sig,
                        // timelocks can't be dissatisfied, so here we ignore a_nsat and only consider c_sat
                        relative_timelock: c_sat.relative_timelock,
                        absolute_timelock: c_sat.absolute_timelock,
                    },
                )
            }
            Terminal::OrB(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let l_nsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let r_nsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );

                assert!(!l_nsat.has_sig);
                assert!(!r_nsat.has_sig);

                min_fn(
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                        relative_timelock: r_sat.relative_timelock,
                        absolute_timelock: r_sat.absolute_timelock,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_nsat.stack, l_sat.stack),
                        has_sig: l_sat.has_sig,
                        relative_timelock: l_sat.relative_timelock,
                        absolute_timelock: l_sat.absolute_timelock,
                    },
                )
            }
            Terminal::OrD(ref l, ref r) | Terminal::OrC(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let l_nsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );

                assert!(!l_nsat.has_sig);

                min_fn(
                    l_sat,
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                        relative_timelock: r_sat.relative_timelock,
                        absolute_timelock: r_sat.absolute_timelock,
                    },
                )
            }
            Terminal::OrI(ref l, ref r) => {
                let l_sat =
                    Self::satisfy_helper(&l.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let r_sat =
                    Self::satisfy_helper(&r.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                min_fn(
                    Satisfaction {
                        stack: Witness::combine(l_sat.stack, Witness::push_1()),
                        has_sig: l_sat.has_sig,
                        relative_timelock: l_sat.relative_timelock,
                        absolute_timelock: l_sat.absolute_timelock,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, Witness::push_0()),
                        has_sig: r_sat.has_sig,
                        relative_timelock: r_sat.relative_timelock,
                        absolute_timelock: r_sat.absolute_timelock,
                    },
                )
            }
            Terminal::Thresh(k, ref subs) => {
                thresh_fn(k, subs, stfr, root_has_sig, leaf_hash, min_fn)
            }
            Terminal::Multi(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = Vec::with_capacity(k);
                for pk in keys {
                    match Witness::signature::<_, Ctx>(stfr, pk, leaf_hash) {
                        Witness::Stack(sig) => {
                            sigs.push(sig);
                            sig_count += 1;
                        }
                        Witness::Impossible => {}
                        Witness::Unavailable => unreachable!(
                            "Signature satisfaction without witness must be impossible"
                        ),
                    }
                }

                if sig_count < k {
                    Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                        relative_timelock: None,
                        absolute_timelock: None,
                    }
                } else {
                    // Throw away the most expensive ones
                    for _ in 0..sig_count - k {
                        let max_idx = sigs
                            .iter()
                            .enumerate()
                            .max_by_key(|&(_, v)| v.len())
                            .unwrap()
                            .0;
                        sigs[max_idx] = vec![];
                    }

                    Satisfaction {
                        stack: sigs.into_iter().fold(Witness::push_0(), |acc, sig| {
                            Witness::combine(acc, Witness::Stack(sig))
                        }),
                        has_sig: true,
                        relative_timelock: None,
                        absolute_timelock: None,
                    }
                }
            }
            Terminal::MultiA(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = vec![vec![Placeholder::PushZero]; keys.len()];
                for (i, pk) in keys.iter().rev().enumerate() {
                    match Witness::signature::<_, Ctx>(stfr, pk, leaf_hash) {
                        Witness::Stack(sig) => {
                            sigs[i] = sig;
                            sig_count += 1;
                            // This a privacy issue, we are only selecting the first available
                            // sigs. Incase pk at pos 1 is not selected, we know we did not have access to it
                            // bitcoin core also implements the same logic for MULTISIG, so I am not bothering
                            // permuting the sigs for now
                            if sig_count == k {
                                break;
                            }
                        }
                        Witness::Impossible => {}
                        Witness::Unavailable => unreachable!(
                            "Signature satisfaction without witness must be impossible"
                        ),
                    }
                }

                if sig_count < k {
                    Satisfaction {
                        stack: Witness::Impossible,
                        has_sig: false,
                        relative_timelock: None,
                        absolute_timelock: None,
                    }
                } else {
                    Satisfaction {
                        stack: sigs.into_iter().fold(Witness::empty(), |acc, sig| {
                            Witness::combine(acc, Witness::Stack(sig))
                        }),
                        has_sig: true,
                        relative_timelock: None,
                        absolute_timelock: None,
                    }
                }
            }
        }
    }

    // Helper function to produce a dissatisfaction
    fn dissatisfy_helper<Ctx, Sat, F, G>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
        min_fn: &mut F,
        thresh_fn: &mut G,
    ) -> Self
    where
        Ctx: ScriptContext,
        Sat: AssetProvider<Pk>,
        F: FnMut(
            Satisfaction<Placeholder<Pk>>,
            Satisfaction<Placeholder<Pk>>,
        ) -> Satisfaction<Placeholder<Pk>>,
        G: FnMut(
            usize,
            &[Arc<Miniscript<Pk, Ctx>>],
            &Sat,
            bool,
            &TapLeafHash,
            &mut F,
        ) -> Satisfaction<Placeholder<Pk>>,
    {
        match *term {
            Terminal::PkK(..) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::PkH(ref pk) => Satisfaction {
                stack: Witness::combine(
                    Witness::push_0(),
                    Witness::pkh_public_key::<_, Ctx>(stfr, &pk.to_pubkeyhash(Ctx::sig_type())),
                ),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::RawPkH(ref pkh) => Satisfaction {
                stack: Witness::combine(
                    Witness::push_0(),
                    Witness::pkh_public_key::<_, Ctx>(stfr, pkh),
                ),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::False => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::True => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Older(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::After(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Sha256(_)
            | Terminal::Hash256(_)
            | Terminal::Ripemd160(_)
            | Terminal::Hash160(_) => Satisfaction {
                stack: Witness::hash_dissatisfaction(),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => {
                Self::dissatisfy_helper(&sub.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn)
            }
            Terminal::DupIf(_) | Terminal::NonZero(_) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Verify(_) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::AndV(ref v, ref other) => {
                let vsat =
                    Self::satisfy_helper(&v.node, stfr, root_has_sig, leaf_hash, min_fn, thresh_fn);
                let odissat = Self::dissatisfy_helper(
                    &other.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(odissat.stack, vsat.stack),
                    has_sig: vsat.has_sig || odissat.has_sig,
                    relative_timelock: None,
                    absolute_timelock: None,
                }
            }
            Terminal::AndB(ref l, ref r)
            | Terminal::OrB(ref l, ref r)
            | Terminal::OrD(ref l, ref r)
            | Terminal::AndOr(ref l, _, ref r) => {
                let lnsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let rnsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                Satisfaction {
                    stack: Witness::combine(rnsat.stack, lnsat.stack),
                    has_sig: rnsat.has_sig || lnsat.has_sig,
                    relative_timelock: None,
                    absolute_timelock: None,
                }
            }
            Terminal::OrC(..) => Satisfaction {
                stack: Witness::Impossible,
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::OrI(ref l, ref r) => {
                let lnsat = Self::dissatisfy_helper(
                    &l.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let dissat_1 = Satisfaction {
                    stack: Witness::combine(lnsat.stack, Witness::push_1()),
                    has_sig: lnsat.has_sig,
                    relative_timelock: None,
                    absolute_timelock: None,
                };

                let rnsat = Self::dissatisfy_helper(
                    &r.node,
                    stfr,
                    root_has_sig,
                    leaf_hash,
                    min_fn,
                    thresh_fn,
                );
                let dissat_2 = Satisfaction {
                    stack: Witness::combine(rnsat.stack, Witness::push_0()),
                    has_sig: rnsat.has_sig,
                    relative_timelock: None,
                    absolute_timelock: None,
                };

                // Dissatisfactions don't need to non-malleable. Use minimum_mall always
                Satisfaction::minimum_mall(dissat_1, dissat_2)
            }
            Terminal::Thresh(_, ref subs) => Satisfaction {
                stack: subs.iter().fold(Witness::empty(), |acc, sub| {
                    let nsat = Self::dissatisfy_helper(
                        &sub.node,
                        stfr,
                        root_has_sig,
                        leaf_hash,
                        min_fn,
                        thresh_fn,
                    );
                    assert!(!nsat.has_sig);
                    Witness::combine(nsat.stack, acc)
                }),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::Multi(k, _) => Satisfaction {
                stack: Witness::Stack(vec![Placeholder::PushZero; k + 1]),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
            Terminal::MultiA(_, ref pks) => Satisfaction {
                stack: Witness::Stack(vec![Placeholder::PushZero; pks.len()]),
                has_sig: false,
                relative_timelock: None,
                absolute_timelock: None,
            },
        }
    }
}

impl Satisfaction<Placeholder<DefiniteDescriptorKey>> {
    pub(crate) fn into_plan(self, desc_type: DescriptorType) -> Option<Plan> {
        if let Witness::Stack(stack) = self.stack {
            Some(Plan {
                desc_type,
                template: WitnessTemplate::from_placeholder_stack(stack),
                absolute_timelock: self.absolute_timelock.map(Into::into),
                relative_timelock: self.relative_timelock,
            })
        } else {
            None
        }
    }
}

impl Satisfaction<Vec<u8>> {
    /// Produce a satisfaction non-malleable satisfaction
    pub(super) fn satisfy<Ctx, Pk, Sat>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        Ctx: ScriptContext,
        Pk: MiniscriptKey + ToPublicKey,
        Sat: Satisfier<Pk>,
    {
        Satisfaction::<Placeholder<Pk>>::build_template(term, &stfr, root_has_sig, leaf_hash)
            .map_stack(|stack| {
                WitnessTemplate::from_placeholder_stack(stack)
                    .try_completing(stfr)
                    .expect("the same satisfier should manage to complete the template")
            })
    }

    /// Produce a satisfaction(possibly malleable)
    pub(super) fn satisfy_mall<Ctx, Pk, Sat>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
        root_has_sig: bool,
        leaf_hash: &TapLeafHash,
    ) -> Self
    where
        Ctx: ScriptContext,
        Pk: MiniscriptKey + ToPublicKey,
        Sat: Satisfier<Pk>,
    {
        Satisfaction::<Placeholder<Pk>>::build_template_mall(term, &stfr, root_has_sig, leaf_hash)
            .map_stack(|stack| {
                WitnessTemplate::from_placeholder_stack(stack)
                    .try_completing(stfr)
                    .expect("the same satisfier should manage to complete the template")
            })
    }
}
