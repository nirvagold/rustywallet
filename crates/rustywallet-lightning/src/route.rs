//! Route hints for Lightning payments.
//!
//! This module provides types for working with route hints,
//! which help payers find a path to private channels.

use crate::channel::ShortChannelId;
use crate::node::NodeId;

/// A route hint for finding a path to a destination.
///
/// Route hints are used when the destination has private channels
/// that are not publicly announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHint {
    /// Hops in this route hint
    hops: Vec<RouteHintHop>,
}

impl RouteHint {
    /// Create a new empty route hint.
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    /// Create a route hint with the given hops.
    pub fn with_hops(hops: Vec<RouteHintHop>) -> Self {
        Self { hops }
    }

    /// Add a hop to the route hint.
    pub fn add_hop(&mut self, hop: RouteHintHop) {
        self.hops.push(hop);
    }

    /// Get the hops in this route hint.
    pub fn hops(&self) -> &[RouteHintHop] {
        &self.hops
    }

    /// Get the number of hops.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Check if the route hint is empty.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

impl Default for RouteHint {
    fn default() -> Self {
        Self::new()
    }
}

/// A single hop in a route hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHintHop {
    /// Public key of the node at the start of this hop
    pub src_node_id: NodeId,
    /// Short channel ID
    pub short_channel_id: ShortChannelId,
    /// Base fee in millisatoshis
    pub fee_base_msat: u32,
    /// Proportional fee in millionths
    pub fee_proportional_millionths: u32,
    /// CLTV expiry delta
    pub cltv_expiry_delta: u16,
}

impl RouteHintHop {
    /// Create a new route hint hop.
    pub fn new(
        src_node_id: NodeId,
        short_channel_id: ShortChannelId,
        fee_base_msat: u32,
        fee_proportional_millionths: u32,
        cltv_expiry_delta: u16,
    ) -> Self {
        Self {
            src_node_id,
            short_channel_id,
            fee_base_msat,
            fee_proportional_millionths,
            cltv_expiry_delta,
        }
    }

    /// Calculate the fee for routing a given amount.
    pub fn fee_for_amount(&self, amount_msat: u64) -> u64 {
        let base = self.fee_base_msat as u64;
        let proportional = (amount_msat * self.fee_proportional_millionths as u64) / 1_000_000;
        base + proportional
    }
}

/// Builder for creating route hints.
pub struct RouteHintBuilder {
    hops: Vec<RouteHintHop>,
}

impl RouteHintBuilder {
    /// Create a new route hint builder.
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    /// Add a hop to the route hint.
    pub fn hop(
        mut self,
        src_node_id: NodeId,
        short_channel_id: ShortChannelId,
        fee_base_msat: u32,
        fee_proportional_millionths: u32,
        cltv_expiry_delta: u16,
    ) -> Self {
        self.hops.push(RouteHintHop::new(
            src_node_id,
            short_channel_id,
            fee_base_msat,
            fee_proportional_millionths,
            cltv_expiry_delta,
        ));
        self
    }

    /// Build the route hint.
    pub fn build(self) -> RouteHint {
        RouteHint::with_hops(self.hops)
    }
}

impl Default for RouteHintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        NodeId::from_bytes([2u8; 33])
    }

    #[test]
    fn test_route_hint_creation() {
        let hint = RouteHint::new();
        assert!(hint.is_empty());
    }

    #[test]
    fn test_route_hint_with_hops() {
        let hop = RouteHintHop::new(
            test_node_id(),
            ShortChannelId::new(700000, 1, 0),
            1000,
            100,
            144,
        );

        let hint = RouteHint::with_hops(vec![hop]);
        assert_eq!(hint.len(), 1);
    }

    #[test]
    fn test_fee_calculation() {
        let hop = RouteHintHop::new(
            test_node_id(),
            ShortChannelId::new(700000, 1, 0),
            1000,  // 1 sat base fee
            1000,  // 0.1% proportional
            144,
        );

        // For 1,000,000 msat (1000 sats):
        // base: 1000 msat
        // proportional: 1,000,000 * 1000 / 1,000,000 = 1000 msat
        // total: 2000 msat
        assert_eq!(hop.fee_for_amount(1_000_000), 2000);
    }

    #[test]
    fn test_route_hint_builder() {
        let hint = RouteHintBuilder::new()
            .hop(
                test_node_id(),
                ShortChannelId::new(700000, 1, 0),
                1000,
                100,
                144,
            )
            .hop(
                test_node_id(),
                ShortChannelId::new(700001, 2, 1),
                500,
                50,
                40,
            )
            .build();

        assert_eq!(hint.len(), 2);
    }
}
