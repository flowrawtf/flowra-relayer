//! Per-validator PBP policy enforcement.
//!
//! A relayer fronts several validators at once and forwards the same packet batch to each of
//! them. A drop decision is therefore not a property of the relayer, it is a property of the
//! validator the packet is being forwarded to: the validator is the party accountable for what
//! lands in its own block, and it is the only party with standing to say what may be dropped on
//! its behalf. Dropping globally would censor one tenant's block by another tenant's rules.
//!
//! So there is no operator-local rule file here. Policy arrives over
//! `Relayer::ProvidePbpPolicy` from an authenticated validator identity, is stored under that
//! identity, and applies only when forwarding to it.
//!
//! Extraction is separated from evaluation because of the fan-out: a packet is parsed once into
//! a [`PacketSummary`], and every subscribed validator's policy is then evaluated against that
//! summary. Parsing per (packet x validator) would multiply the most expensive step by the
//! number of tenants.

use std::collections::{HashMap, HashSet};

use dashmap::DashMap;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;

/// What a policy can be evaluated against, extracted from a packet exactly once.
pub struct PacketSummary {
    /// Every account the transaction references, static keys plus anything resolved through an
    /// address lookup table. Matching on references rather than on the program id is what makes
    /// `program_blacklist` hold when a malicious program is reached through a router.
    pub account_keys: Vec<Pubkey>,
    /// `(program_id, instruction_data)` for each top-level instruction. Inner (CPI)
    /// instructions are not on the wire and cannot appear here.
    pub instructions: Vec<(Pubkey, Vec<u8>)>,
}

impl PacketSummary {
    /// Returns `None` only when the transaction cannot be parsed at all.
    ///
    /// A lookup table that is missing from the cache leaves the loaded addresses out rather than
    /// guessing at them: a partial address list shifts every subsequent index and would resolve
    /// accounts to the wrong pubkeys, which can only produce false positives. Dropping
    /// fee-paying flow that was never listed is the worse failure, so unresolved means unmatched.
    pub fn extract(
        tx: &VersionedTransaction,
        address_lookup_table_cache: &DashMap<Pubkey, AddressLookupTableAccount>,
    ) -> Self {
        let static_keys = tx.message.static_account_keys();
        let mut account_keys = static_keys.to_vec();
        if let Some(loaded) = loaded_addresses(tx, address_lookup_table_cache) {
            account_keys.extend(loaded);
        }

        let instructions = tx
            .message
            .instructions()
            .iter()
            .filter_map(|ix| {
                account_keys
                    .get(ix.program_id_index as usize)
                    .map(|program_id| (*program_id, ix.data.clone()))
            })
            .collect();

        Self {
            account_keys,
            instructions,
        }
    }
}

/// The subset of a validator's PBP policy the relayer is able to act on.
///
/// The relayer sees individual packets, not bundles, so bundle-scoped policy (searcher
/// whitelists, CU quotas, priority pinning) is not represented: those belong to the block
/// engine, which is where bundles exist.
#[derive(Default, Clone)]
pub struct PbpFilter {
    /// Transactions referencing one of these accounts are dropped.
    pub address_blacklist: HashSet<Pubkey>,
    /// Programs blocked wholesale, matched on account references so that reaching the program
    /// through a router does not evade the rule.
    pub program_blacklist: HashSet<Pubkey>,
    /// program id -> blocked instruction-data prefixes. An empty prefix list blocks every
    /// top-level instruction to that program.
    pub instruction_blacklist: HashMap<Pubkey, Vec<Vec<u8>>>,
}

/// Why a packet was dropped, for the counter it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbpDrop {
    Address,
    Program,
    Instruction,
}

impl PbpFilter {
    pub fn is_empty(&self) -> bool {
        self.address_blacklist.is_empty()
            && self.program_blacklist.is_empty()
            && self.instruction_blacklist.is_empty()
    }

    /// Returns why this packet must not be forwarded to the validator that set this policy, or
    /// `None` if it may be.
    pub fn evaluate(&self, summary: &PacketSummary) -> Option<PbpDrop> {
        if self.is_empty() {
            return None;
        }

        for key in &summary.account_keys {
            if self.address_blacklist.contains(key) {
                return Some(PbpDrop::Address);
            }
            if self.program_blacklist.contains(key) {
                return Some(PbpDrop::Program);
            }
        }

        for (program_id, data) in &summary.instructions {
            if let Some(prefixes) = self.instruction_blacklist.get(program_id) {
                if prefixes.is_empty() || prefixes.iter().any(|p| data.starts_with(p.as_slice())) {
                    return Some(PbpDrop::Instruction);
                }
            }
        }

        None
    }
}

/// The message's lookup-table-loaded addresses, in the order the runtime appends them to the
/// static keys: every table's writable entries first, then every table's readonly entries.
///
/// `None` if any referenced table is missing from the cache; see [`PacketSummary::extract`].
fn loaded_addresses(
    tx: &VersionedTransaction,
    address_lookup_table_cache: &DashMap<Pubkey, AddressLookupTableAccount>,
) -> Option<Vec<Pubkey>> {
    let lookups = tx.message.address_table_lookups()?;

    let mut writable = Vec::new();
    let mut readonly = Vec::new();
    for table in lookups {
        let info = address_lookup_table_cache.get(&table.account_key)?;
        for idx in &table.writable_indexes {
            writable.push(*info.addresses.get(*idx as usize)?);
        }
        for idx in &table.readonly_indexes {
            readonly.push(*info.addresses.get(*idx as usize)?);
        }
    }

    writable.extend(readonly);
    Some(writable)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use dashmap::DashMap;
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::{
        compiled_instruction::CompiledInstruction, v0, v0::MessageAddressTableLookup,
        AddressLookupTableAccount, MessageHeader, VersionedMessage,
    };
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;
    use solana_transaction::{versioned::VersionedTransaction, Transaction};

    use super::{PacketSummary, PbpDrop, PbpFilter};

    fn tx_invoking(program: Pubkey, account: Pubkey, data: &[u8]) -> VersionedTransaction {
        let payer = Keypair::new();
        VersionedTransaction::from(Transaction::new_signed_with_payer(
            &[Instruction::new_with_bytes(
                program,
                data,
                vec![AccountMeta {
                    pubkey: account,
                    is_signer: false,
                    is_writable: false,
                }],
            )],
            Some(&payer.pubkey()),
            &[&payer],
            Hash::default(),
        ))
    }

    /// A v0 transaction whose program id lives in a lookup table rather than the static keys.
    fn tx_invoking_via_lookup_table(
        table_key: Pubkey,
        writable: Vec<u8>,
        readonly: Vec<u8>,
        program_id_index: u8,
        data: &[u8],
    ) -> VersionedTransaction {
        let payer = Keypair::new();
        let message = VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            recent_blockhash: Hash::new_unique(),
            account_keys: vec![payer.pubkey()],
            address_table_lookups: vec![MessageAddressTableLookup {
                account_key: table_key,
                writable_indexes: writable,
                readonly_indexes: readonly,
            }],
            instructions: vec![CompiledInstruction {
                program_id_index,
                accounts: vec![0],
                data: data.to_vec(),
            }],
        });
        VersionedTransaction::try_new(message, &[&payer]).expect("valid tx")
    }

    fn filter_with_instruction(program: Pubkey, prefixes: Vec<Vec<u8>>) -> PbpFilter {
        PbpFilter {
            instruction_blacklist: HashMap::from_iter([(program, prefixes)]),
            ..PbpFilter::default()
        }
    }

    #[test]
    fn an_empty_policy_drops_nothing() {
        let cache = DashMap::new();
        let tx = tx_invoking(Pubkey::new_unique(), Pubkey::new_unique(), &[1, 2, 3]);
        let summary = PacketSummary::extract(&tx, &cache);
        assert_eq!(PbpFilter::default().evaluate(&summary), None);
    }

    #[test]
    fn a_program_is_blocked_wholesale_by_account_reference() {
        let cache = DashMap::new();
        let program = Pubkey::new_unique();
        let tx = tx_invoking(program, Pubkey::new_unique(), &[9]);
        let summary = PacketSummary::extract(&tx, &cache);

        let filter = PbpFilter {
            program_blacklist: HashSet::from_iter([program]),
            ..PbpFilter::default()
        };
        assert_eq!(filter.evaluate(&summary), Some(PbpDrop::Program));
    }

    /// The reason program_blacklist matches references rather than the program id slot: a
    /// transaction that only *mentions* the program still hits it.
    #[test]
    fn a_referenced_program_is_blocked_even_when_another_program_is_invoked() {
        let cache = DashMap::new();
        let malicious = Pubkey::new_unique();
        let router = Pubkey::new_unique();
        let tx = tx_invoking(router, malicious, &[0]);
        let summary = PacketSummary::extract(&tx, &cache);

        let filter = PbpFilter {
            program_blacklist: HashSet::from_iter([malicious]),
            ..PbpFilter::default()
        };
        assert_eq!(filter.evaluate(&summary), Some(PbpDrop::Program));
    }

    #[test]
    fn an_address_is_blocked_by_reference() {
        let cache = DashMap::new();
        let addr = Pubkey::new_unique();
        let tx = tx_invoking(Pubkey::new_unique(), addr, &[0]);
        let summary = PacketSummary::extract(&tx, &cache);

        let filter = PbpFilter {
            address_blacklist: HashSet::from_iter([addr]),
            ..PbpFilter::default()
        };
        assert_eq!(filter.evaluate(&summary), Some(PbpDrop::Address));
    }

    #[test]
    fn an_instruction_rule_matches_only_its_data_prefix() {
        let cache = DashMap::new();
        let program = Pubkey::new_unique();
        let tx = tx_invoking(program, Pubkey::new_unique(), &[0xDE, 0xAD, 0x01]);
        let summary = PacketSummary::extract(&tx, &cache);

        assert_eq!(
            filter_with_instruction(program, vec![vec![0xDE, 0xAD]]).evaluate(&summary),
            Some(PbpDrop::Instruction)
        );
        assert_eq!(
            filter_with_instruction(program, vec![vec![0xBE, 0xEF]]).evaluate(&summary),
            None
        );
        // An empty prefix list blocks every instruction to the program.
        assert_eq!(
            filter_with_instruction(program, vec![]).evaluate(&summary),
            Some(PbpDrop::Instruction)
        );
        assert_eq!(
            filter_with_instruction(Pubkey::new_unique(), vec![vec![0xDE, 0xAD]])
                .evaluate(&summary),
            None
        );
    }

    #[test]
    fn a_program_id_hidden_in_a_lookup_table_is_still_matched() {
        let program = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let cache = DashMap::from_iter([(
            table_key,
            AddressLookupTableAccount {
                key: table_key,
                addresses: vec![Pubkey::new_unique(), program],
            },
        )]);

        // 1 static key (the payer), so loaded addresses start at index 1. The table contributes
        // one writable (table idx 0) then one readonly (table idx 1 = the program) -> index 2.
        let tx = tx_invoking_via_lookup_table(table_key, vec![0], vec![1], 2, &[0xDE, 0xAD, 0x01]);
        let summary = PacketSummary::extract(&tx, &cache);

        assert_eq!(
            filter_with_instruction(program, vec![vec![0xDE, 0xAD]]).evaluate(&summary),
            Some(PbpDrop::Instruction)
        );
    }

    #[test]
    fn an_uncached_lookup_table_lets_the_transaction_through_rather_than_guessing() {
        let program = Pubkey::new_unique();
        let table_key = Pubkey::new_unique();
        let cache = DashMap::new(); // table never fetched

        let tx = tx_invoking_via_lookup_table(table_key, vec![0], vec![1], 2, &[0xDE, 0xAD, 0x01]);
        let summary = PacketSummary::extract(&tx, &cache);

        // Must not drop: with the table unresolved we cannot know which program this is, and a
        // false positive here removes a fee-paying transaction from the block.
        assert_eq!(
            filter_with_instruction(program, vec![vec![0xDE, 0xAD]]).evaluate(&summary),
            None
        );
    }

    /// The property the whole per-validator design exists for.
    #[test]
    fn one_validators_policy_does_not_drop_for_another() {
        let cache = DashMap::new();
        let program = Pubkey::new_unique();
        let tx = tx_invoking(program, Pubkey::new_unique(), &[1]);
        let summary = PacketSummary::extract(&tx, &cache);

        let strict = PbpFilter {
            program_blacklist: HashSet::from_iter([program]),
            ..PbpFilter::default()
        };
        let permissive = PbpFilter::default();

        assert_eq!(strict.evaluate(&summary), Some(PbpDrop::Program));
        assert_eq!(permissive.evaluate(&summary), None);
    }
}
