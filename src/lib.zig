//! UDP Proxy 2020 - Zig Library
//!
//! Public API for the UDP proxy library.
//! Can be used as a standalone library or via the CLI.

const std = @import("std");

pub const pcap = @import("pcap.zig");
pub const packet = @import("packet.zig");
pub const bpf = @import("bpf.zig");
pub const client_cache = @import("client_cache.zig");
pub const sender = @import("sender.zig");
pub const listener = @import("listener.zig");

// Re-export main types
pub const Handle = pcap.Handle;
pub const LinkType = pcap.LinkType;
pub const Interface = pcap.Interface;
pub const InterfaceAddress = pcap.InterfaceAddress;

pub const EthernetHeader = packet.EthernetHeader;
pub const IPv4Header = packet.IPv4Header;
pub const UdpHeader = packet.UdpHeader;
pub const ParsedPacket = packet.ParsedPacket;
pub const PacketBuilder = packet.PacketBuilder;

pub const ClientCache = client_cache.ClientCache;
pub const SendPktFeed = sender.SendPktFeed;
pub const SendPacket = sender.SendPacket;
pub const Listener = listener.Listener;
pub const ListenerConfig = listener.ListenerConfig;
pub const UdpSink = listener.UdpSink;

// Utility functions
pub const findAllDevices = pcap.findAllDevices;
pub const freeDevices = pcap.freeDevices;
pub const findLoopback = pcap.findLoopback;
pub const parseIpv4 = pcap.parseIpv4;
pub const formatIpv4 = pcap.formatIpv4;

pub const parsePacket = packet.parsePacket;
pub const calculateIpChecksum = packet.calculateIpChecksum;
pub const calculateBroadcast = packet.calculateBroadcast;
pub const calculateNetwork = packet.calculateNetwork;
pub const prefixToNetmask = packet.prefixToNetmask;
pub const netmaskToPrefix = packet.netmaskToPrefix;

pub const buildFilter = bpf.buildFilter;
pub const buildPortFilter = bpf.buildPortFilter;

pub const buildOutgoingPacket = sender.buildOutgoingPacket;

// Version info
pub const version = "0.1.0";

// ============================================================================
// Tests
// ============================================================================

test {
    // Run tests from all submodules
    std.testing.refAllDecls(@This());
}
