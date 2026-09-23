use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(target_os = "linux")]
use std::fs;

use transfer_protocol::{Candidate, CandidateId, CandidateKind};

use crate::ProbeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub address: IpAddr,
    pub prefix_len: u8,
    pub is_loopback: bool,
    pub is_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRoute {
    pub interface_name: String,
    pub interface_index: Option<u32>,
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    interfaces: Vec<NetworkInterface>,
    routes: Vec<NetworkRoute>,
}

impl NetworkSnapshot {
    pub fn collect() -> Result<Self, ProbeError> {
        let interfaces = collect_interfaces()?;
        let routes = collect_routes(&interfaces);
        Ok(Self { interfaces, routes })
    }

    pub fn new(interfaces: Vec<NetworkInterface>, routes: Vec<NetworkRoute>) -> Self {
        Self { interfaces, routes }
    }

    pub fn interfaces(&self) -> &[NetworkInterface] {
        &self.interfaces
    }

    pub fn routes(&self) -> &[NetworkRoute] {
        &self.routes
    }

    pub fn candidates(
        &self,
        port: u16,
        max_candidates: usize,
    ) -> Result<Vec<Candidate>, ProbeError> {
        if max_candidates == 0 {
            return Err(ProbeError::InvalidConfig("max_candidates"));
        }
        if port == 0 {
            return Err(ProbeError::InvalidConfig("candidate port"));
        }

        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        for interface in self
            .interfaces
            .iter()
            .filter(|interface| interface.is_up && !interface.is_loopback)
        {
            let address = std::net::SocketAddr::new(interface.address, port);
            if !seen.insert(address) {
                continue;
            }
            let priority = if self.has_default_route(interface) {
                100
            } else {
                90
            };
            candidates.push(Candidate {
                id: CandidateId::random().map_err(|_| ProbeError::RandomnessUnavailable)?,
                kind: CandidateKind::Host,
                address: Some(address),
                priority,
                interface_index: Some(interface.index),
            });
        }

        candidates.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.address.cmp(&right.address))
        });
        candidates.truncate(max_candidates);
        if candidates.is_empty() {
            return Err(ProbeError::NoCandidates);
        }
        Ok(candidates)
    }

    fn has_default_route(&self, interface: &NetworkInterface) -> bool {
        self.routes.iter().any(|route| {
            route.interface_index == Some(interface.index)
                && route.is_default
                && route.destination.is_unspecified()
        })
    }
}

#[cfg(unix)]
fn collect_interfaces() -> Result<Vec<NetworkInterface>, ProbeError> {
    use std::{ffi::CStr, ptr};

    let mut head = ptr::null_mut();
    // SAFETY: getifaddrs initializes a linked list owned by the caller. Every pointer is
    // checked before dereferencing and the list is released exactly once below.
    let result = unsafe { libc::getifaddrs(&mut head) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut interfaces = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: current is a node from the list returned by getifaddrs.
        let item = unsafe { &*current };
        if !item.ifa_name.is_null() && !item.ifa_addr.is_null() && !item.ifa_netmask.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string owned by the OS list.
            let name = unsafe { CStr::from_ptr(item.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            if let (Some(address), Some(netmask)) =
                (unsafe { sockaddr_ip(item.ifa_addr, family) }, unsafe {
                    sockaddr_ip(item.ifa_netmask, family)
                })
            {
                let prefix_len = prefix_len(netmask);
                let index = unsafe { libc::if_nametoindex(item.ifa_name) };
                let is_loopback = (item.ifa_flags as i32 & libc::IFF_LOOPBACK) != 0;
                let is_up = (item.ifa_flags as i32 & libc::IFF_UP) != 0;
                interfaces.push(NetworkInterface {
                    name,
                    index,
                    address,
                    prefix_len,
                    is_loopback,
                    is_up,
                });
            }
        }
        // SAFETY: current points to a valid node; advancing follows the OS-owned list.
        current = unsafe { (*current).ifa_next };
    }
    // SAFETY: head was initialized by a successful getifaddrs call.
    unsafe { libc::freeifaddrs(head) };

    interfaces.sort_by(|left, right| {
        left.index
            .cmp(&right.index)
            .then_with(|| left.address.cmp(&right.address))
    });
    interfaces.dedup_by(|left, right| left.index == right.index && left.address == right.address);
    Ok(interfaces)
}

#[cfg(not(unix))]
fn collect_interfaces() -> Result<Vec<NetworkInterface>, ProbeError> {
    Err(ProbeError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface enumeration is not supported on this platform",
    )))
}

#[cfg(unix)]
unsafe fn sockaddr_ip(address: *const libc::sockaddr, family: i32) -> Option<IpAddr> {
    match family {
        libc::AF_INET => {
            // SAFETY: the family and the caller-provided sockaddr storage identify sockaddr_in.
            let address = unsafe { *(address as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                address.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family and the caller-provided sockaddr storage identify sockaddr_in6.
            let address = unsafe { *(address as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn prefix_len(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(mask) => mask
            .octets()
            .iter()
            .map(|byte| byte.count_ones() as u8)
            .sum(),
        IpAddr::V6(mask) => mask
            .octets()
            .iter()
            .map(|byte| byte.count_ones() as u8)
            .sum(),
    }
}

fn collect_routes(interfaces: &[NetworkInterface]) -> Vec<NetworkRoute> {
    let mut routes = Vec::new();
    #[cfg(target_os = "linux")]
    {
        routes.extend(read_linux_ipv4_routes(interfaces));
        routes.extend(read_linux_ipv6_routes(interfaces));
    }
    routes
}

#[cfg(target_os = "linux")]
fn read_linux_ipv4_routes(interfaces: &[NetworkInterface]) -> Vec<NetworkRoute> {
    let Ok(contents) = fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 {
                return None;
            }
            let destination = u32::from_str_radix(fields[1], 16).ok()?;
            let gateway = u32::from_str_radix(fields[2], 16).ok()?;
            let mask = u32::from_str_radix(fields[7], 16).ok()?;
            let interface_index = interfaces
                .iter()
                .find(|interface| interface.name == fields[0])
                .map(|interface| interface.index);
            let destination = Ipv4Addr::from(destination.to_le());
            let gateway = Ipv4Addr::from(gateway.to_le());
            let mask = Ipv4Addr::from(mask.to_le());
            Some(NetworkRoute {
                interface_name: fields[0].to_owned(),
                interface_index,
                destination: IpAddr::V4(destination),
                prefix_len: prefix_len(IpAddr::V4(mask)),
                gateway: (gateway != Ipv4Addr::UNSPECIFIED).then_some(IpAddr::V4(gateway)),
                is_default: destination == Ipv4Addr::UNSPECIFIED,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn read_linux_ipv6_routes(interfaces: &[NetworkInterface]) -> Vec<NetworkRoute> {
    let Ok(contents) = fs::read_to_string("/proc/net/ipv6_route") else {
        return Vec::new();
    };
    contents
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10 {
                return None;
            }
            let destination = parse_ipv6_hex(fields[0])?;
            let prefix_len = u8::from_str_radix(fields[1], 16).ok()?;
            let gateway = parse_ipv6_hex(fields[4])?;
            let interface_name = fields[9].to_owned();
            let interface_index = interfaces
                .iter()
                .find(|interface| interface.name == interface_name)
                .map(|interface| interface.index);
            Some(NetworkRoute {
                interface_name,
                interface_index,
                destination: IpAddr::V6(destination),
                prefix_len,
                gateway: (gateway != Ipv6Addr::UNSPECIFIED).then_some(IpAddr::V6(gateway)),
                is_default: destination == Ipv6Addr::UNSPECIFIED,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_ipv6_hex(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_default_is_detected() {
        let interface = NetworkInterface {
            name: "eth0".into(),
            index: 2,
            address: "192.0.2.1".parse().unwrap(),
            prefix_len: 24,
            is_loopback: false,
            is_up: true,
        };
        let snapshot = NetworkSnapshot::new(
            vec![interface],
            vec![NetworkRoute {
                interface_name: "eth0".into(),
                interface_index: Some(2),
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
                gateway: Some("192.0.2.254".parse().unwrap()),
                is_default: true,
            }],
        );
        let candidates = snapshot.candidates(4000, 4).unwrap();
        assert_eq!(candidates[0].priority, 100);
    }
}
