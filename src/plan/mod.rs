// TODO: copyright etc
#![allow(unused)]
#![allow(missing_docs)]
//! A spending plan or *plan* for short is a representation of a particular spending path on a
//! descriptor. This allows us to analayze a choice of spending path without producing any
//! signatures or other witness data for it.
//!
//! To make a plan you provide the descriptor with "assets" like which keys you are able to use, hash
//! pre-images you have access to, the current block height etc.
//!
//! Once you've got a plan it can tell you its expected satisfaction weight which can be useful for
//! doing coin selection. Furthermore it provides which subset of those keys and hash pre-images you
//! will actually need as well as what locktime or sequence number you need to set.
//!
//! Once you've obstained signatures, hash pre-images etc required by the plan, it can create a
//! witness/script_sig for the input.

use crate::descriptor::Bare;
use crate::miniscript::Miniscript;
use crate::{DefiniteDescriptorKey, Descriptor, ScriptContext, Terminal};
use bitcoin::hashes::sha256;
use bitcoin::util::bip32::KeySource;
use bitcoin::{LockTime, Sequence};
use std::cmp::Ordering;
use std::collections::HashSet;

pub struct Plan {}

pub struct Assets {
    keys: HashSet<DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: HashSet<sha256::Hash>,
    absolute_timelock: Timelock<LockTime>, // restrizioni
    relative_timelock: Timelock<Sequence>, // restrizioni
}

impl Assets {
    fn has_key(&self, k: &DefiniteDescriptorKey) -> bool {
        // Piú check: fingerprint, canderive ecc
        self.keys.contains(k)
    }
}

// TODO change name
pub struct Timelock<T> {
    at_least: Option<T>,
    at_most: Option<T>,
}

pub enum TimelockError {
    IncompatibleTimelocks,
    AtLeastGreaterThanAtMost,
}

impl<T: PartialOrd + Clone> Timelock<T> {
    fn new(at_least: Option<T>, at_most: Option<T>) -> Result<Self, TimelockError> {
        if let (Some(l), Some(m)) = (&at_least, &at_most) {
            match l.partial_cmp(&m) {
                None => return Err(TimelockError::IncompatibleTimelocks),
                Some(Ordering::Greater) => return Err(TimelockError::AtLeastGreaterThanAtMost),
                _ => {}
            }
        }

        Ok(Timelock { at_least, at_most })
    }

    fn replace_at_most(&mut self, at_most: Option<T>) -> Result<(), TimelockError> {
        *self = Timelock::new(self.at_least.clone(), at_most)?;
        Ok(())
    }

    fn replace_at_least(&mut self, at_least: Option<T>) -> Result<(), TimelockError> {
        *self = Timelock::new(at_least, self.at_most.clone())?;
        Ok(())
    }

    fn get_plannable(&self, to_compare: T) -> Plannable {
        let Timelock { at_least, at_most } = &self;

        match at_most {
            Some(m) if !m.partial_cmp(&to_compare).is_none() || to_compare > *m => {
                return Plannable::Impossible;
            }
            _ => {}
        }

        match at_least {
            Some(l) if !l.partial_cmp(&to_compare).is_none() => Plannable::Impossible,
            Some(l) if to_compare < *l => Plannable::new_optimal_only(0),
            _ => Plannable::new_with_timelock(0),
        }
    }
}

impl Descriptor<DefiniteDescriptorKey> {
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        match *self {
            Descriptor::Bare(ref bare) => bare.plan(assets),
            _ => todo!(),
            /*
            Descriptor::Pkh(ref pkh) => pkh.get_satisfaction(satisfier),
            Descriptor::Wpkh(ref wpkh) => wpkh.get_satisfaction(satisfier),
            Descriptor::Wsh(ref wsh) => wsh.get_satisfaction(satisfier),
            Descriptor::Sh(ref sh) => sh.get_satisfaction(satisfier),
            Descriptor::Tr(ref tr) => tr.get_satisfaction(satisfier),
            */
        }
    }
}

impl Bare<DefiniteDescriptorKey> {
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        self.as_inner().plan(assets)
    }
}

impl<Ctx: ScriptContext> Miniscript<DefiniteDescriptorKey, Ctx> {
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        let plannable = plan_helper(&self.node, assets);
        todo!()
    }
}

fn plan_helper<Ctx: ScriptContext>(
    node: &Terminal<DefiniteDescriptorKey, Ctx>,
    assets: &Assets,
) -> Plannable {
    match node {
        Terminal::True => Plannable::new_optimal_only(1),
        Terminal::False => Plannable::new_optimal_only(1),
        Terminal::PkH(pk) | Terminal::PkK(pk) | Terminal::RawPkH(pk) => {
            if assets.has_key(pk) {
                Plannable::new_optimal_only(Ctx::pk_len(pk))
            } else {
                Plannable::Impossible
            }
        }
        // absolute
        Terminal::After(t) => assets.absolute_timelock.get_plannable(t.into()),
        // relative
        Terminal::Older(t) => assets.relative_timelock.get_plannable(*t),
        Terminal::Sha256(h) => {
            if assets.sha256_preimages.contains(h) {
                Plannable::new_optimal_only(33)
            } else {
                Plannable::Impossible
            }
        }
        Terminal::Alt(ms)
        | Terminal::Swap(ms)
        | Terminal::Check(ms)
        | Terminal::DupIf(ms)
        | Terminal::Verify(ms)
        | Terminal::NonZero(ms)
        | Terminal::ZeroNotEqual(ms) => plan_helper(&ms.node, assets),
        Terminal::AndV(ms1, ms2) | Terminal::AndB(ms1, ms2) => {
            plan_helper(&ms1.node, assets).merge_and(plan_helper(&ms2.node, assets))
        }
        _ => todo!(),
    }
}

struct Solution {
    weight: usize,
    items: Assets,
}

#[derive(Debug, Clone)]
enum Plannable {
    Weight {
        // in byte
        optimal: usize,
        with_timelock: Option<usize>,
    },
    Impossible,
}

impl Plannable {
    fn new_optimal_only(optimal: usize) -> Self {
        Plannable::Weight {
            optimal,
            with_timelock: None,
        }
    }

    fn new_with_timelock(optimal: usize) -> Self {
        Plannable::Weight {
            optimal,
            with_timelock: Some(optimal),
        }
    }

    fn merge_and(a: Plannable, b: Plannable) -> Self {
        match (a, b) {
            (Plannable::Impossible, _) | (_, Plannable::Impossible) => Plannable::Impossible,
            (
                Plannable::Weight {
                    optimal: a_optimal,
                    with_timelock: a_timelock,
                },
                Plannable::Weight {
                    optimal: b_optimal,
                    with_timelock: b_timelock,
                },
            ) => {
                let optimal = a_optimal + b_optimal;
                let with_timelock = match (a_timelock, b_timelock) {
                    (None, None) => None,
                    (Some(a), None) => Some(a + b_optimal),
                    (None, Some(b)) => Some(a_optimal + b),
                    (Some(a), Some(b)) => Some(std::cmp::min(a + b_optimal, b + a_optimal)),
                };

                Plannable::Weight {
                    optimal,
                    with_timelock,
                }
            }
        }
    }
}

fn pick_subset(list: Vec<Plannable>, thresh: usize) -> Plannable {
    debug_assert!(thresh > 0);

    // Filter out the impossible items in the list, then sort by optimal weight
    let mut sorted_optimal = list
        .iter()
        .enumerate()
        .filter_map(|(i, p)| match p {
            Plannable::Impossible => None,
            Plannable::Weight { optimal, .. } => Some((i, *optimal)),
        })
        .collect::<Vec<_>>();

    // If there aren't enough item after excluding the `Impossible`, this is also `Impossible`
    if sorted_optimal.len() < thresh {
        return Plannable::Impossible;
    }
    sorted_optimal.sort_unstable_by_key(|(_, p)| *p);

    // Try with all the items that can satisfy the timelock requirement
    let mut with_timelock_list = list
        .iter()
        .enumerate()
        .filter_map(|(i, p)| match p {
            Plannable::Weight {
                with_timelock: Some(wt),
                ..
            } => {
                // We take the current element with timelock weight,
                // then we take the sorted_optimal list, we remove the current element,
                // and we take the thresh - 1 best optimal weight
                Some(
                    wt + sorted_optimal
                        .iter()
                        .filter(|(index, _)| *index != i)
                        .map(|(_, w)| *w)
                        .take(thresh - 1)
                        .sum::<usize>(),
                )
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    // Sort by weight, and the first one is our with_timelock optimal solution
    with_timelock_list.sort_unstable();

    Plannable::Weight {
        optimal: sorted_optimal.iter().take(thresh).map(|(_, w)| *w).sum(),
        with_timelock: with_timelock_list.get(0).cloned(),
    }
}

// Esempio di API
/*
{
    let assets_che_ho = Assets::new().add(keys).add(preimages).add(psbt_input).at_least(10);
    let _tutti = Assets::everything();
    let plan = my_descriptor.plan(&assets)?;
    println!("{}", plan.weight());
    println!("{}", plan.assets_needed());
    plan.try_satisfy(satisfier, psbt, input_index); // or psbt input?
}
*/
