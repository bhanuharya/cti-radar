//! IP global-reachability — exact port of CPython 3.12
//! `ipaddress.ip_address(x).is_global` (the Python scanner's `_is_global_ip`).
//!
//! `is_global = not-in-shared AND not-is_private`, where `is_private` is
//! membership in the IANA special-registry lists minus a few exceptions.
//!
//! NOTE: like CPython, multicast counts as *global* here (224.0.0.0/4,
//! ff00::/8). Callers that must reject multicast do so explicitly.

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

fn in_v4_net(ip: u32, net: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (ip & mask) == (net & mask)
}

fn in_v6_net(ip: u128, net: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (ip & mask) == (net & mask)
}

/// (`_private_networks` for IPv4 in CPython 3.12.)
const V4_PRIVATE: [(u32, u8); 14] = [
    (v4(0, 0, 0, 0), 8),
    (v4(10, 0, 0, 0), 8),
    (v4(127, 0, 0, 0), 8),
    (v4(169, 254, 0, 0), 16),
    (v4(172, 16, 0, 0), 12),
    (v4(192, 0, 0, 0), 24),
    (v4(192, 0, 0, 170), 31),
    (v4(192, 0, 2, 0), 24),
    (v4(192, 168, 0, 0), 16),
    (v4(198, 18, 0, 0), 15),
    (v4(198, 51, 100, 0), 24),
    (v4(203, 0, 113, 0), 24),
    (v4(240, 0, 0, 0), 4),
    (v4(255, 255, 255, 255), 32),
];

/// (`_private_networks_exceptions` for IPv4: PCP anycast — globally reachable.)
const V4_PRIVATE_EXCEPTIONS: [(u32, u8); 2] =
    [(v4(192, 0, 0, 9), 32), (v4(192, 0, 0, 10), 32)];

/// (`_public_network` for IPv4: shared address space — neither global nor private.)
const V4_SHARED: (u32, u8) = (v4(100, 64, 0, 0), 10);

/// (`_private_networks` for IPv6 in CPython 3.12.)
const V6_PRIVATE: [(u128, u8); 10] = [
    (0x00000000_00000000_00000000_00000001, 128), // ::1/128
    (0x00000000_00000000_00000000_00000000, 128), // ::/128
    (0x00000000_00000000_0000ffff_00000000, 96),  // ::ffff:0:0/96
    (0x0064ff9b_00010000_00000000_00000000, 48),  // 64:ff9b:1::/48
    (0x01000000_00000000_00000000_00000000, 64),  // 100::/64
    (0x20010000_00000000_00000000_00000000, 23),  // 2001::/23
    (0x20010db8_00000000_00000000_00000000, 32),  // 2001:db8::/32
    (0x20020000_00000000_00000000_00000000, 16),  // 2002::/16
    (0xfc000000_00000000_00000000_00000000, 7),   // fc00::/7
    (0xfe800000_00000000_00000000_00000000, 10),  // fe80::/10
];

/// (`_private_networks_exceptions` for IPv6.)
const V6_PRIVATE_EXCEPTIONS: [(u128, u8); 6] = [
    (0x20010001_00000000_00000000_00000001, 128), // 2001:1::1/128
    (0x20010001_00000000_00000000_00000002, 128), // 2001:1::2/128
    (0x20010003_00000000_00000000_00000000, 32),  // 2001:3::/32
    (0x20010004_01120000_00000000_00000000, 48),  // 2001:4:112::/48
    (0x20010020_00000000_00000000_00000000, 28),  // 2001:20::/28
    (0x20010030_00000000_00000000_00000000, 28),  // 2001:30::/28
];

/// v4 `is_private` on raw bits: in the private list minus exceptions.
/// NOTE: 100.64.0.0/10 (shared) is NOT private here — CPython excludes it
/// from `is_private` (it only fails `is_global` via `_public_network`).
fn is_private_v4_bits(n: u32) -> bool {
    let private = V4_PRIVATE
        .iter()
        .any(|(net, prefix)| in_v4_net(n, *net, *prefix));
    let excepted = V4_PRIVATE_EXCEPTIONS
        .iter()
        .any(|(net, prefix)| in_v4_net(n, *net, *prefix));
    private && !excepted
}

/// v4 `is_global` on the raw u32 (shared by native v4 and v4-mapped v6).
fn is_global_v4_bits(n: u32) -> bool {
    !in_v4_net(n, V4_SHARED.0, V4_SHARED.1) && !is_private_v4_bits(n)
}

/// Exact `ip.is_global` semantics (unparseable input -> false, like Python's
/// `try/except -> False`).
pub fn is_global_ip(ip: &str) -> bool {
    let ip = ip.trim();
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4a)) => is_global_v4_bits(v4a.into()),
        Ok(std::net::IpAddr::V6(v6a)) => {
            let n: u128 = v6a.into();
            // IPv4-mapped: `is_global == !is_private`, and `is_private`
            // delegates to the UNDERLYING IPv4 `is_private` (CPython parity —
            // note 100.64.0.0/10 is not v4-private, so ::ffff:100.64.0.1
            // counts as global, exactly like CPython).
            if in_v6_net(n, 0x00000000_00000000_0000ffff_00000000, 96) {
                return !is_private_v4_bits((n & 0xffff_ffff) as u32);
            }
            let private = V6_PRIVATE
                .iter()
                .any(|(net, prefix)| in_v6_net(n, *net, *prefix));
            let excepted = V6_PRIVATE_EXCEPTIONS
                .iter()
                .any(|(net, prefix)| in_v6_net(n, *net, *prefix));
            !private || excepted
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Truth table generated from CPython 3.12 `ipaddress.is_global`.
    const CASES: [(&str, bool); 47] = [
        ("8.8.8.8", true),
        ("1.1.1.1", true),
        ("10.0.0.1", false),
        ("172.16.0.1", false),
        ("172.31.255.255", false),
        ("192.168.1.1", false),
        ("127.0.0.1", false),
        ("169.254.169.254", false),
        // multicast counts as global in CPython (quirk, preserved for parity)
        ("224.0.0.1", true),
        ("255.255.255.255", false),
        ("0.0.0.0", false),
        ("0.0.0.1", false),
        ("100.64.0.1", false),
        ("100.127.255.255", false),
        ("192.0.0.1", false),
        ("192.0.0.9", true),
        ("192.0.0.10", true),
        ("192.0.0.170", false),
        ("192.0.2.1", false),
        ("198.51.100.1", false),
        ("203.0.113.1", false),
        ("198.18.0.1", false),
        ("240.0.0.1", false),
        ("241.1.2.3", false),
        ("192.31.196.1", true),
        ("192.52.193.1", true),
        ("192.88.99.1", true),
        ("192.175.48.1", true),
        ("::1", false),
        ("::", false),
        ("fe80::1", false),
        ("fc00::1", false),
        ("ff02::1", true),
        ("2001:db8::1", false),
        ("2001::1", false),
        ("2001:1::1", true),
        ("2001:1::2", true),
        ("2001:3::9", true),
        ("::ffff:8.8.8.8", true),
        ("::ffff:10.0.0.1", false),
        ("::ffff:100.64.0.1", true),
        ("::ffff:0.0.0.0", false),
        ("::ffff:127.0.0.1", false),
        ("64:ff9b::808:808", true),
        ("100::1", false),
        ("2002::1", false),
        ("not-an-ip", false),
    ];

    #[test]
    fn test_is_global_ip_matches_cpython() {
        for (addr, want) in CASES {
            assert_eq!(is_global_ip(addr), want, "mismatch for {}", addr);
        }
    }
}
