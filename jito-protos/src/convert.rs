use solana_perf::packet::PacketRef;

use crate::packet::{Meta as ProtoMeta, Packet as ProtoPacket, PacketFlags as ProtoPacketFlags};

/// Takes a `PacketRef` rather than `&Packet`: a 4.2 `PacketBatch` may hold pinned or
/// `Bytes`-backed packets, and its iterators hand out the ref enum for either.
pub fn packet_to_proto_packet(p: PacketRef<'_>) -> Option<ProtoPacket> {
    Some(ProtoPacket {
        data: p.data(..)?.to_vec(),
        meta: Some(ProtoMeta {
            size: p.meta().size as u64,
            addr: p.meta().addr.to_string(),
            port: p.meta().port as u32,
            flags: Some(ProtoPacketFlags {
                discard: p.meta().discard(),
                forwarded: p.meta().forwarded(),
                repair: p.meta().repair(),
                simple_vote_tx: p.meta().is_simple_vote_tx(),
                tracer_packet: p.meta().is_perf_track_packet(),
                from_staked_node: p.meta().is_from_staked_node(),
            }),
            sender_stake: 0,
        }),
    })
}
