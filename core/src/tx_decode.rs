//! One decode for every transaction version the cluster accepts.
//!
//! `bincode::deserialize::<VersionedTransaction>` reads the signature array first, as a
//! shortvec, and the message after it. Transaction v1 (SIMD-0385) inverts that: byte 0 is the
//! message version prefix `0x81`, the message body follows, and the signatures sit at the end
//! as a fixed-length array with no length prefix. Handed a v1 packet, bincode reads `0x81` as
//! the first byte of a shortvec, decodes a signature count of 129 and runs off the end of the
//! buffer. That is an error, not a mis-parse, and both forwarding legs treated the error as
//! "not a transaction":
//!
//!   * `relayer::forward_packets` skips what it cannot deserialize, and it deserializes
//!     whenever an OFAC list is configured or a connected validator has a live PBP policy.
//!     Under either, every v1 transaction would be dropped before the validator we front ever
//!     saw it — lost fees in a block we build ourselves.
//!   * `block_engine::filter_packets` forwards only what it could deserialize, so the block
//!     engine and every searcher behind it would see no v1 traffic at all, policy or not.
//!
//! `wincode` is the codec the runtime uses for packets (agave's `block_creation_loop`
//! deserializes a packet exactly this way) and it dispatches on that first byte: below `0x80`
//! it is a legacy/v0 shortvec signature count, `0x81` is v1. One call covers all three.

use solana_transaction::versioned::VersionedTransaction;

/// Decode a transaction of any version from raw packet bytes, or `None` when the bytes are not
/// a transaction. Legacy, v0 and v1 all go through here.
#[inline]
pub fn deserialize_transaction(data: &[u8]) -> Option<VersionedTransaction> {
    wincode::deserialize::<VersionedTransaction>(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKHASH: [u8; 32] = [7u8; 32];
    const PAYER: [u8; 32] = [1u8; 32];
    const PROGRAM: [u8; 32] = [2u8; 32];

    /// A v1 transaction, built byte by byte from the wire format in
    /// `solana_message::v1::message`: prefix, header, config mask, blockhash, counts,
    /// addresses, config values, instruction headers, payloads, then the signatures.
    fn transaction_v1() -> Vec<u8> {
        let mut b = vec![0x81];
        b.extend_from_slice(&[1, 0, 1]); // 1 required signature, 0 ro signed, 1 ro unsigned
        b.extend_from_slice(&0u32.to_le_bytes()); // config mask: no configured values
        b.extend_from_slice(&BLOCKHASH);
        b.push(1); // num_instructions
        b.push(2); // num_addresses
        b.extend_from_slice(&PAYER);
        b.extend_from_slice(&PROGRAM);
        // instruction header: program_id_index, num_accounts, data_len (u16 LE)
        b.extend_from_slice(&[1, 1]);
        b.extend_from_slice(&3u16.to_le_bytes());
        b.push(0); // account index
        b.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // instruction data
        b.extend_from_slice(&[9u8; 64]); // the one signature, unprefixed, last
        b
    }

    /// A legacy transaction: shortvec signature count, then the message.
    fn transaction_legacy() -> Vec<u8> {
        let mut b = vec![1]; // one signature
        b.extend_from_slice(&[9u8; 64]);
        b.extend_from_slice(&[1, 0, 1]); // header
        b.push(2); // shortvec: 2 account keys
        b.extend_from_slice(&PAYER);
        b.extend_from_slice(&PROGRAM);
        b.extend_from_slice(&BLOCKHASH);
        b.push(1); // shortvec: 1 instruction
        b.push(1); // program_id_index
        b.push(1); // shortvec: 1 account index
        b.push(0);
        b.push(3); // shortvec: 3 data bytes
        b.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        b
    }

    #[test]
    fn a_v1_transaction_decodes_and_keeps_its_fields() {
        let tx = deserialize_transaction(&transaction_v1()).expect("v1 decodes");
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.message.static_account_keys().len(), 2);
        assert_eq!(tx.message.static_account_keys()[0].to_bytes(), PAYER);
        assert_eq!(tx.message.recent_blockhash().to_bytes(), BLOCKHASH);
        assert_eq!(tx.message.instructions().len(), 1);
    }

    /// The reason this module exists: the codec we replaced cannot read the bytes above.
    #[test]
    fn bincode_cannot_read_a_v1_transaction() {
        assert!(bincode::deserialize::<VersionedTransaction>(&transaction_v1()).is_err());
    }

    #[test]
    fn legacy_still_decodes_through_the_same_call() {
        let tx = deserialize_transaction(&transaction_legacy()).expect("legacy decodes");
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.message.static_account_keys()[1].to_bytes(), PROGRAM);
        assert_eq!(tx.message.recent_blockhash().to_bytes(), BLOCKHASH);
    }

    #[test]
    fn garbage_is_not_a_transaction() {
        assert!(deserialize_transaction(&[0xFF; 40]).is_none());
        assert!(deserialize_transaction(&[]).is_none());
    }
}
