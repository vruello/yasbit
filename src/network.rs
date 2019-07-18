use std::net;

use crate::message;

pub trait NetAddrBase {
    fn bytes(&self) -> Vec<u8>;
}

pub struct NetAddr {
    time: u32,
    net_addr_version: NetAddrVersion
}

impl NetAddrBase for NetAddr {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.time.to_le_bytes());
        bytes.extend_from_slice(
            self.net_addr_version.bytes().as_slice());
        bytes
    }
}

impl NetAddr {
    pub fn new(time: u32, services: u64, ip: net::Ipv6Addr, port: u16) -> Self {
        NetAddr {
            time,
            net_addr_version: NetAddrVersion::new(services, ip, port)
        }
    }
}

pub struct NetAddrVersion {
    services: u64,
    ip: net::Ipv6Addr,
    port: u16
}

impl NetAddrBase for NetAddrVersion {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.services.to_le_bytes());
        bytes.extend_from_slice(&self.ip.octets());
        // Port is in network format: big endian
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes
    }
}

impl NetAddrVersion {
    pub fn new(services: u64, ip: net::Ipv6Addr, port: u16) -> Self {
        NetAddrVersion {
            services,
            ip,
            port
        }
    }
}

#[cfg(test)]
mod tests {
   
    use super::*;

    #[test]
    fn test_net_addr_version() {
        let net_addr_version = NetAddrVersion::new(
            message::NODE_NETWORK,
            net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
            8333);

        assert_eq!(
            "010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr_version.bytes())
        );

        let net_addr_version = NetAddrVersion::new(
            message::NODE_NETWORK,
            "::ffff:a00:1".parse().unwrap(),
            8333);


        assert_eq!(
            "010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr_version.bytes())
        );
    }

    #[test]
    fn test_net_addr() {
        let net_addr = NetAddr::new(
            1563472788, // time
            message::NODE_NETWORK,
            net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
            8333);

        assert_eq!(
            "94b3305d010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr.bytes())
        );

        let net_addr = NetAddr::new(
            1563472788, // time
            message::NODE_NETWORK,
            "::ffff:a00:1".parse().unwrap(),
            8333);


        assert_eq!(
            "94b3305d010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr.bytes())
        );
    }
}
