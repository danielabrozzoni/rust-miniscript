// Miniscript
// Written in 2022 by rust-miniscript developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//! A spending plan or *plan* for short is a representation of a particular spending path on a
//! descriptor. This allows us to analayze a choice of spending path without producing any
//! signatures or other witness data for it.
//!
//! To make a plan you provide the descriptor with "assets" like which keys you are able to use, hash
//! pre-images you have access to, absolute/relative timelock constraints etc.
//!
//! Once you've got a plan it can tell you its expected satisfaction weight which can be useful for
//! doing coin selection. Furthermore it provides which subset of those keys and hash pre-images you
//! will actually need as well as what locktime or sequence number you need to set.
//!
//! Once you've obstained signatures, hash pre-images etc required by the plan, it can create a
//! witness/script_sig for the input.

use crate::descriptor::DescriptorType;
use crate::miniscript::satisfy::{Placeholder, Satisfier, WitnessTemplate};
use crate::miniscript::{context::SigType, hash256};
use crate::util::witness_size;
use crate::{DefiniteDescriptorKey, MiniscriptKey, ScriptContext, ToPublicKey};
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{LockTime, Sequence};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// Trait describing a present/missing lookup table for constructing witness templates
///
/// This trait mirrors the [`Satisfier`] trait with the difference that instad of returning the
/// item if it's present, it only returns a boolean to indicate its presence.
///
/// This trait is automatically implemented for every type that is also a satisfier, and simply
/// proxies the queries to the satisfier and returns whether an item is available or not.
///
/// All the methods have a default implementation that returns `false`.
pub trait AssetProvider<Pk: MiniscriptKey> {
    /// Given a public key, look up an ECDSA signature with that key
    fn lookup_ecdsa_sig(&self, _: &Pk) -> bool {
        false
    }

    /// Lookup the tap key spend sig
    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> bool {
        false
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> bool {
        false
    }

    /// Given a raw `Pkh`, lookup corresponding `Pk`. If present, return its lenght.
    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a keyhash, look up the EC signature and the associated key. If present,
    /// return the key lenght.
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a keyhash, look up the schnorr signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_tap_leaf_script_sig(&self, _: &(hash160::Hash, TapLeafHash)) -> bool {
        false
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: &Pk::Sha256) -> bool {
        false
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: &Pk::Hash256) -> bool {
        false
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: &Pk::Ripemd160) -> bool {
        false
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: &Pk::Hash160) -> bool {
        false
    }

    /// Assert whether a relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether an absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }
}

/// Wrapper around [`Assets`] that logs every query and value returned
pub struct LoggerAssetProvider(Assets);

macro_rules! impl_log_method {
    ( $name:ident, $( <$ctx:ident: ScriptContext > )? $( $arg:ident : $ty:ty, )* -> $ret_ty:ty ) => {
        fn $name $( <$ctx: ScriptContext> )? ( &self, $( $arg:$ty ),* ) -> $ret_ty {
            let ret = (self.0).$name $( ::<$ctx> )*( $( $arg ),* );
            dbg!(stringify!( $name ), ( $( $arg ),* ), &ret);

            ret
        }
    }
}

impl AssetProvider<DefiniteDescriptorKey> for LoggerAssetProvider {
    impl_log_method!(lookup_ecdsa_sig, pk: &DefiniteDescriptorKey, -> bool);
    impl_log_method!(lookup_tap_key_spend_sig, pk: &DefiniteDescriptorKey, -> bool);
    impl_log_method!(lookup_tap_leaf_script_sig, pk: &DefiniteDescriptorKey, leaf_hash: &TapLeafHash, -> bool);
    impl_log_method!(lookup_raw_pkh_pk, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_ecdsa_sig, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_tap_leaf_script_sig, hash: &(hash160::Hash, TapLeafHash), -> bool);
    impl_log_method!(lookup_sha256, hash: &sha256::Hash, -> bool);
    impl_log_method!(lookup_hash256, hash: &hash256::Hash, -> bool);
    impl_log_method!(lookup_ripemd160, hash: &ripemd160::Hash, -> bool);
    impl_log_method!(lookup_hash160, hash: &hash160::Hash, -> bool);
    impl_log_method!(check_older, s: Sequence, -> bool);
    impl_log_method!(check_after, t: LockTime, -> bool);
}

impl<T, Pk> AssetProvider<Pk> for T
where
    T: Satisfier<Pk>,
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_ecdsa_sig(&self, pk: &Pk) -> bool {
        Satisfier::lookup_ecdsa_sig(self, pk).is_some()
    }

    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> bool {
        Satisfier::lookup_tap_key_spend_sig(self).is_some()
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, leaf_hash: &TapLeafHash) -> bool {
        Satisfier::lookup_tap_leaf_script_sig(self, pk, leaf_hash).is_some()
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        Satisfier::lookup_raw_pkh_pk(self, hash).map(|p| Ctx::pk_len(&p))
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        Satisfier::lookup_raw_pkh_ecdsa_sig(self, hash).map(|(p, _)| Ctx::pk_len(&p))
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        Satisfier::lookup_raw_pkh_tap_leaf_script_sig(self, hash).is_some()
    }

    fn lookup_sha256(&self, hash: &Pk::Sha256) -> bool {
        Satisfier::lookup_sha256(self, hash).is_some()
    }

    fn lookup_hash256(&self, hash: &Pk::Hash256) -> bool {
        Satisfier::lookup_hash256(self, hash).is_some()
    }

    fn lookup_ripemd160(&self, hash: &Pk::Ripemd160) -> bool {
        Satisfier::lookup_ripemd160(self, hash).is_some()
    }

    fn lookup_hash160(&self, hash: &Pk::Hash160) -> bool {
        Satisfier::lookup_hash160(self, hash).is_some()
    }

    fn check_older(&self, s: Sequence) -> bool {
        Satisfier::check_older(self, s)
    }

    fn check_after(&self, l: LockTime) -> bool {
        Satisfier::check_after(self, l)
    }
}

/// A spending plan or *plan* for short is a representation of a particular spending path on a
/// descriptor. This allows us to analayze a choice of spending path without producing any
/// signatures or other witness data for it.
/// Calling `get_plan` on a Descriptor will return this structure, which contains a Witness
/// Template for the cheapest possible (i.e., considering the `Assets` given) spending path
#[derive(Debug, Clone)]
pub struct Plan {
    /// This plan's witness template
    pub template: WitnessTemplate<Placeholder<DefiniteDescriptorKey>>,
    /// The absolute timelock this plan uses
    pub absolute_timelock: Option<LockTime>,
    /// The relative timelock this plan uses
    pub relative_timelock: Option<Sequence>,

    pub(crate) desc_type: DescriptorType,
}

impl Plan {
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        self.desc_type.segwit_version()
    }

    /// The weight, in witness units, needed for satisfying this plan (includes both
    /// the script sig size and the witness size)
    pub fn satisfaction_weight(&self) -> usize {
        self.witness_size() + self.scriptsig_size() * 4
    }

    /// The weight, in witness units, of the script sig that satisfies this plan
    pub fn scriptsig_size(&self) -> usize {
        match (self.desc_type.segwit_version(), self.desc_type) {
            // Entire witness goes in the script_sig
            (None, _) => witness_size(self.template.as_ref()),
            // Taproot doesn't have a "wrapped" version (scriptSig len (1))
            (Some(WitnessVersion::V1), _) => 1,
            // scriptSig len (1) + OP_0 (1) + OP_PUSHBYTES_20 (1) + <pk hash> (20)
            (_, DescriptorType::ShWpkh) => 1 + 1 + 1 + 20,
            // scriptSig len (1) + OP_0 (1) + OP_PUSHBYTES_32 (1) + <script hash> (32)
            (_, DescriptorType::ShWsh) | (_, DescriptorType::ShWshSortedMulti) => 1 + 1 + 1 + 32,
            // Native Segwit v0 (scriptSig len (1))
            __ => 1,
        }
    }

    /// The weight, in witness units, of the witness that satisfies this plan
    pub fn witness_size(&self) -> usize {
        if let Some(_) = self.desc_type.segwit_version() {
            witness_size(self.template.as_ref())
        } else {
            0 // should be 1 if there's at least one segwit input in the tx, but that's out of
              // scope as we can't possibly know that just by looking at the descriptor
        }
    }
}

/// The Assets we can use to satisfy a particular spending path
#[derive(Debug, Default)]
pub struct Assets {
    keys: HashMap<hash160::Hash, DefiniteDescriptorKey>,
    tap_key_spend_sigs: HashMap<hash160::Hash, bitcoin::SchnorrSig>,
    ecdsa_signatures: HashMap<hash160::Hash, (bitcoin::EcdsaSig, usize)>,
    schnorr_signatures: HashMap<(hash160::Hash, TapLeafHash), (bitcoin::SchnorrSig, usize)>,
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Option<LockTime>,
    relative_timelock: Option<Sequence>,
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        let pkh = pk.to_pubkeyhash(SigType::Ecdsa);
        let we_have_pk = self.keys.contains_key(&pkh);
        let we_have_sig = self.ecdsa_signatures.contains_key(&pkh);
        we_have_pk || we_have_sig
    }

    fn lookup_tap_key_spend_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        let pkh = pk.to_pubkeyhash(SigType::Ecdsa);
        let we_have_pk = self.keys.contains_key(&pkh);
        let we_have_sig = self.tap_key_spend_sigs.contains_key(&pkh);
        we_have_pk || we_have_sig
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> bool {
        let pkh = pk.to_pubkeyhash(SigType::Schnorr);
        let we_have_pk = self.keys.contains_key(&pkh);
        let we_have_sig = self.schnorr_signatures.contains_key(&(pkh, *tap_leaf_hash));
        we_have_pk || we_have_sig
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        self.keys.get(hash).map(|p| Ctx::pk_len(p))
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        let we_have_pk = self.keys.get(hash).map(|p| Ctx::pk_len(p));
        let we_have_sig = self.ecdsa_signatures.get(hash).map(|(_, l)| *l);
        we_have_pk.or(we_have_sig)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        let we_have_pk = self.keys.contains_key(&hash.0);
        let we_have_sig = self.schnorr_signatures.contains_key(&hash);
        we_have_pk || we_have_sig
    }

    fn lookup_sha256(&self, hash: &sha256::Hash) -> bool {
        self.sha256_preimages.contains(hash)
    }

    fn lookup_hash256(&self, hash: &hash256::Hash) -> bool {
        self.hash256_preimages.contains(hash)
    }

    fn lookup_ripemd160(&self, hash: &ripemd160::Hash) -> bool {
        self.ripemd160_preimages.contains(hash)
    }

    fn lookup_hash160(&self, hash: &hash160::Hash) -> bool {
        self.hash160_preimages.contains(hash)
    }

    fn check_older(&self, s: Sequence) -> bool {
        if let Some(rt) = &self.relative_timelock {
            return rt.is_relative_lock_time()
                && rt.is_height_locked() == s.is_height_locked()
                && s <= *rt;
        }

        false
    }

    fn check_after(&self, l: LockTime) -> bool {
        if let Some(at) = &self.absolute_timelock {
            return l.partial_cmp(at) == Some(Ordering::Less);
        }

        false
    }
}

/// Conversion into a `Assets`
pub trait IntoAssets {
    /// Convert `self` into a `Assets` struct
    fn into_assets(self) -> Assets;
}

impl IntoAssets for DefiniteDescriptorKey {
    fn into_assets(self) -> Assets {
        vec![self].into_assets()
    }
}

impl IntoAssets for Vec<DefiniteDescriptorKey> {
    fn into_assets(self) -> Assets {
        Assets {
            keys: self
                .into_iter()
                .map(|pk| {
                    vec![
                        (pk.to_pubkeyhash(SigType::Ecdsa), pk.clone()),
                        (pk.to_pubkeyhash(SigType::Schnorr), pk),
                    ]
                })
                .flatten()
                .collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for sha256::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            sha256_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for hash256::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            hash256_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for ripemd160::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            ripemd160_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for hash160::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            hash160_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for Assets {
    fn into_assets(self) -> Assets {
        self
    }
}

impl Assets {
    /// Contruct an empty instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add some assets
    pub fn add<A: IntoAssets>(mut self, asset: A) -> Self {
        self.append(asset.into_assets());
        self
    }

    /// Set the maximum relative timelock allowed
    pub fn older(mut self, seq: Sequence) -> Self {
        self.relative_timelock = Some(seq);
        self
    }

    /// Set the maximum absolute timelock allowed
    pub fn after(mut self, lt: LockTime) -> Self {
        self.absolute_timelock = Some(lt);
        self
    }

    fn append(&mut self, b: Self) {
        self.keys.extend(b.keys.into_iter());
        self.sha256_preimages.extend(b.sha256_preimages.into_iter());
        self.hash256_preimages
            .extend(b.hash256_preimages.into_iter());
        self.ripemd160_preimages
            .extend(b.ripemd160_preimages.into_iter());
        self.hash160_preimages
            .extend(b.hash160_preimages.into_iter());

        self.relative_timelock = b.relative_timelock.or(self.relative_timelock);
        self.absolute_timelock = b.absolute_timelock.or(self.absolute_timelock);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::miniscript::satisfy::Witness;
    use crate::*;
    use bitcoin::{LockTime, Sequence};
    use std::str::FromStr;

    #[test]
    fn test_plan() {
        let key = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let desc = format!("wsh(and_v(or_c(pk(023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4),v:older(12960)),pk({}/1/2/*)))", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();

        let def_key = DefiniteDescriptorKey::from_str(&format!("{}/1/2/3", key)).unwrap();

        let assets = Assets::new()
            .add(def_key)
            .older(Sequence::from_height(12960));

        let result = desc.at_derivation_index(3).get_plan(&assets);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().relative_timelock,
            Some(bitcoin::Sequence(12960))
        );
    }

    fn test_inner(
        desc: &str,
        keys: Vec<DefiniteDescriptorKey>,
        tests: Vec<(
            Vec<usize>,
            Option<Sequence>,
            Option<LockTime>,
            Option<usize>,
        )>,
    ) {
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&desc).unwrap();

        for (key_indexes, older, after, expected) in tests {
            let mut assets = Assets::new();
            if let Some(seq) = older {
                assets = assets.older(seq);
            }
            if let Some(locktime) = after {
                assets = assets.after(locktime);
            }
            for ki in key_indexes {
                assets = assets.add(keys[ki].clone());
            }

            let result = desc.get_plan(&assets);
            assert_eq!(
                result.as_ref().map(|plan| plan.satisfaction_weight()),
                expected,
                "{:?}",
                result
            );
        }
    }

    #[test]
    fn test_or() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];

        // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig)
        let tests = vec![
            (vec![], None, None, None),
            (vec![0], None, None, Some(4 + 1 + 73)),
            (vec![0, 1], None, None, Some(4 + 1 + 73)),
        ];

        let desc = format!("wsh(t:or_c(pk({}),v:pkh({})))", keys[0], keys[1]);
        test_inner(&desc, keys, tests);
    }

    #[test]
    fn test_and() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];

        // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2
        let tests = vec![
            (vec![], None, None, None),
            (vec![0], None, None, None),
            (vec![0, 1], None, None, Some(4 + 1 + 73 * 2)),
        ];

        let desc = format!("wsh(and_v(v:pk({}),pk({})))", keys[0], keys[1]);
        test_inner(&desc, keys, tests);
    }

    #[test]
    fn test_multi() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
            )
            .unwrap(),
        ];

        let tests = vec![
            (vec![], None, None, None),
            (vec![0, 1], None, None, None),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 3 + 1 (dummy push)
            (vec![0, 1, 3], None, None, Some(4 + 1 + 73 * 3 + 1)),
        ];

        let desc = format!(
            "wsh(multi(3,{},{},{},{}))",
            keys[0], keys[1], keys[2], keys[3]
        );
        test_inner(&desc, keys, tests);
    }

    #[test]
    fn test_thresh() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];

        let tests = vec![
            (vec![], None, None, None),
            (vec![], Some(Sequence(1000)), None, None),
            (vec![0], None, None, None),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (vec![0], Some(Sequence(1000)), None, Some(80)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (vec![0, 1], None, None, Some(153)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (vec![0, 1], Some(Sequence(1000)), None, Some(80)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (
                vec![0, 1],
                Some(Sequence::from_512_second_intervals(10)),
                None,
                Some(153),
            ), // incompatible timelock
        ];

        let desc = format!(
            "wsh(thresh(2,pk({}),s:pk({}),snl:older(144)))",
            keys[0], keys[1]
        );
        test_inner(&desc, keys.clone(), tests);

        let tests = vec![
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (
                vec![0],
                None,
                Some(LockTime::from_height(1000).unwrap()),
                Some(80),
            ),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (
                vec![0, 1],
                None,
                Some(LockTime::from_time(500_001_000).unwrap()),
                Some(153),
            ), // incompatible timelock
        ];

        let desc = format!(
            "wsh(thresh(2,pk({}),s:pk({}),snl:after(144)))",
            keys[0], keys[1]
        );
        test_inner(&desc, keys, tests);
    }
}
