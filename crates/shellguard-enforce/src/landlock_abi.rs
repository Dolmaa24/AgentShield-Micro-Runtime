//! The arithmetic of Landlock's network rights, kept where it can be tested.
//!
//! `linux/landlock.rs` only compiles on Linux, and there is no Linux host in this
//! project's development environment, so anything decided in there is decided
//! untested. The one decision that is pure arithmetic — *which* network rights a
//! profile's ruleset should handle — lives here instead, compiled everywhere, so
//! it can be checked on the machine the code is written on. Nothing in this module
//! talks to a kernel.
//!
//! # How Landlock network rights work, since the bug was in misreading it
//!
//! A ruleset *handles* a set of rights. A handled right is **denied unless a rule
//! explicitly allows it**; an unhandled right is not restricted at all. The rules
//! for TCP are per-port, and this project adds none. So handling a right means
//! forbidding it outright, and *not* handling it means permitting it outright.
//!
//! To let a command connect out but never listen, the ruleset must therefore
//! handle `BIND_TCP` and leave `CONNECT_TCP` unhandled. It used to handle both
//! whenever the profile was not "connect and listen", so a profile granted only
//! `net.connect` — `pip install`, `git fetch`, the ordinary grant — had its
//! connect denied on any kernel with ABI 4.
//!
//! # What this does not cover
//!
//! Landlock's network rules (ABI 4 through 6) cover TCP `bind` and `connect` only.
//! They say nothing about UDP or Unix-domain sockets, so a profile with *no* network
//! is still able to send datagrams. See DESIGN.md § 16.

// Only Linux's Landlock backend calls this; elsewhere it exists to be tested. The
// allowance is scoped to exactly those platforms so a genuinely unused item on
// Linux would still be reported.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::profile::Profile;

/// ABI 4: bind a TCP socket to a local port.
pub const NET_BIND_TCP: u64 = 1 << 0;
/// ABI 4: connect a TCP socket to a remote port.
pub const NET_CONNECT_TCP: u64 = 1 << 1;

/// The network rights a kernel at this Landlock ABI understands.
///
/// Asking for more than the kernel knows makes ruleset creation fail outright, so
/// the request is masked to this.
pub fn handled_net_for_abi(abi: u32) -> u64 {
    if abi >= 4 {
        NET_BIND_TCP | NET_CONNECT_TCP
    } else {
        0
    }
}

/// The network rights the ruleset for `p` should handle, i.e. forbid.
///
/// | profile                 | handled                | effect                       |
/// |-------------------------|------------------------|------------------------------|
/// | no network              | bind and connect       | neither                      |
/// | network, no listening   | bind only              | connect out, never listen    |
/// | network and listening   | nothing                | unrestricted                 |
///
/// A profile that listens without network (a hand-built inconsistency) is treated
/// as having no network: listening cannot be granted without the network it
/// listens on.
pub fn net_rights_to_handle(p: &Profile, abi: u32) -> u64 {
    let supported = handled_net_for_abi(abi);
    match (p.allow_network, p.allow_listen) {
        (false, _) => supported,
        (true, false) => supported & NET_BIND_TCP,
        (true, true) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(network: bool, listen: bool) -> Profile {
        let mut p = Profile::locked_down("/ws");
        p.allow_network = network;
        p.allow_listen = listen;
        p
    }

    #[test]
    fn a_kernel_before_abi_four_has_no_network_rights_to_handle() {
        for abi in 0..4 {
            assert_eq!(handled_net_for_abi(abi), 0, "ABI {abi}");
            for (n, l) in [(false, false), (true, false), (true, true), (false, true)] {
                assert_eq!(
                    net_rights_to_handle(&profile(n, l), abi),
                    0,
                    "ABI {abi} net={n} listen={l}"
                );
            }
        }
    }

    #[test]
    fn a_profile_with_no_network_forbids_both_connecting_and_binding() {
        let h = net_rights_to_handle(&profile(false, false), 4);
        assert_eq!(h, NET_BIND_TCP | NET_CONNECT_TCP);
    }

    #[test]
    fn a_profile_granted_network_but_not_listening_can_connect_and_cannot_bind() {
        // The bug: this case used to handle BOTH rights, and with no port rules
        // added a handled right is denied — so the grant of `net.connect` did not
        // let the command connect to anything.
        let h = net_rights_to_handle(&profile(true, false), 4);
        assert_eq!(h & NET_CONNECT_TCP, 0, "connect is still forbidden despite the network grant");
        assert_ne!(h & NET_BIND_TCP, 0, "listening should stay forbidden");
        assert_eq!(h, NET_BIND_TCP);
    }

    #[test]
    fn a_profile_that_listens_is_unrestricted() {
        assert_eq!(net_rights_to_handle(&profile(true, true), 4), 0);
    }

    #[test]
    fn listening_without_network_is_treated_as_no_network() {
        // Listening on a network the profile does not have is not a thing to grant.
        let h = net_rights_to_handle(&profile(false, true), 4);
        assert_eq!(h, NET_BIND_TCP | NET_CONNECT_TCP);
    }

    #[test]
    fn the_result_never_asks_for_a_right_the_kernel_does_not_know() {
        for abi in 0..8 {
            for (n, l) in [(false, false), (true, false), (true, true), (false, true)] {
                let h = net_rights_to_handle(&profile(n, l), abi);
                assert_eq!(h & !handled_net_for_abi(abi), 0, "ABI {abi} net={n} listen={l}");
            }
        }
    }

    #[test]
    fn granting_network_never_forbids_more_than_withholding_it() {
        // Monotonic: each step of granting can only remove restrictions.
        let none = net_rights_to_handle(&profile(false, false), 5);
        let connect = net_rights_to_handle(&profile(true, false), 5);
        let both = net_rights_to_handle(&profile(true, true), 5);
        assert_eq!(connect & !none, 0);
        assert_eq!(both & !connect, 0);
        assert!(
            none.count_ones() > connect.count_ones() && connect.count_ones() > both.count_ones()
        );
    }
}
