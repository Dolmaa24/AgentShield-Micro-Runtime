//! seccomp-BPF: refusing syscalls that no confined command has a reason to
//! make.
//!
//! # What this layer is for, and what it is not
//!
//! seccomp filters on syscall *number and register arguments*, not on paths.
//! It cannot express "may write under /workspace" because by the time
//! `openat` is dispatched the filename is a userspace pointer that the filter
//! must not dereference — the memory can be changed by another thread between
//! the check and the use. Filesystem scoping belongs in Landlock, which
//! evaluates in the LSM hooks where the kernel has already resolved the path.
//!
//! What seccomp is good for is removing whole capabilities: no process here
//! needs to load a kernel module, trace another process, or re-enter a
//! namespace, and a syscall that cannot be made is one with no exploitable
//! behaviour.
//!
//! # Why the filter is a denylist and why that is defensible here
//!
//! An allowlist is stronger and is what a single known binary should get. This
//! runs arbitrary developer tooling — compilers, package managers, test
//! harnesses — whose syscall footprint is not enumerable in advance, and an
//! allowlist that breaks `cargo build` gets switched off. The denylist is
//! paired with Landlock, which *is* a default-deny allowlist for the resource
//! that matters most.
//!
//! # io_uring
//!
//! `io_uring_setup` is on the list and it is the least obvious entry. io_uring
//! lets a process submit reads, writes and opens through a shared memory ring
//! that the kernel services without those operations ever passing through the
//! syscall dispatch path seccomp inspects. A seccomp policy that blocks
//! `openat` but permits `io_uring_setup` does not block opening files. Any
//! seccomp sandbox that does not block io_uring has a hole straight through it.

use std::ffi::{c_int, c_ulong};

use crate::profile::{EnforceError, Profile};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
#[derive(Debug)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// Classic BPF opcodes.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Offsets into `struct seccomp_data`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `AUDIT_ARCH_*` values, exposed so a caller can build a filter for an
/// architecture other than the one it is running on — cross-checking a filter
/// in a test, or generating one for a VM guest.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_SECCOMP: c_int = 22;
const SECCOMP_MODE_FILTER: c_ulong = 2;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// The syscalls a confined command is refused, by name.
///
/// Names rather than numbers because the numbers differ per architecture and a
/// table of raw integers is a table nobody can review.
pub const DENIED: &[&str] = &[
    // Debugging another process is reading and writing its memory.
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // Changing the filesystem view defeats every path-based rule above it.
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    // Kernel code loading.
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "bpf",
    // Namespace manipulation is how a process leaves its confinement.
    "unshare",
    "setns",
    // clone3 passes its flags in a struct, so seccomp cannot inspect them;
    // refusing it forces the classic clone, whose flags are in a register.
    "clone3",
    "perf_event_open",
    // The kernel keyring holds credentials.
    "keyctl",
    "add_key",
    "request_key",
    // See the module comment: this one is the whole ballgame.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // userfaultfd turns a page fault into an attacker-controlled pause, which
    // is how time-of-check races get widened into reliable ones.
    "userfaultfd",
    // Reopening a file from a handle bypasses the path it was reached by.
    "name_to_handle_at",
    "open_by_handle_at",
    "reboot",
    "swapon",
    "swapoff",
    "syslog",
    "acct",
    "quotactl",
    // Changing credentials. NO_NEW_PRIVS blocks gaining privilege, but
    // dropping into another uid is still a way to reach files this uid cannot.
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    // READ_IMPLIES_EXEC via personality turns data pages executable.
    "personality",
];

/// Syscall numbers per architecture.
///
/// Kept as an explicit table rather than generated, because a wrong number is
/// a silently missing rule: the filter still loads, still passes its tests, and
/// simply never blocks the syscall it names.
fn syscall_number(name: &str, arch: u32) -> Option<u32> {
    let x86_64 = arch == AUDIT_ARCH_X86_64;
    Some(match name {
        "ptrace" => {
            if x86_64 {
                101
            } else {
                117
            }
        }
        "process_vm_readv" => {
            if x86_64 {
                310
            } else {
                270
            }
        }
        "process_vm_writev" => {
            if x86_64 {
                311
            } else {
                271
            }
        }
        "mount" => {
            if x86_64 {
                165
            } else {
                40
            }
        }
        "umount2" => {
            if x86_64 {
                166
            } else {
                39
            }
        }
        "pivot_root" => {
            if x86_64 {
                155
            } else {
                41
            }
        }
        "chroot" => {
            if x86_64 {
                161
            } else {
                51
            }
        }
        "init_module" => {
            if x86_64 {
                175
            } else {
                105
            }
        }
        "finit_module" => {
            if x86_64 {
                313
            } else {
                273
            }
        }
        "delete_module" => {
            if x86_64 {
                176
            } else {
                106
            }
        }
        "kexec_load" => {
            if x86_64 {
                246
            } else {
                104
            }
        }
        "kexec_file_load" => {
            if x86_64 {
                320
            } else {
                294
            }
        }
        "bpf" => {
            if x86_64 {
                321
            } else {
                280
            }
        }
        "unshare" => {
            if x86_64 {
                272
            } else {
                97
            }
        }
        "setns" => {
            if x86_64 {
                308
            } else {
                268
            }
        }
        "clone3" => 435,
        "perf_event_open" => {
            if x86_64 {
                298
            } else {
                241
            }
        }
        "keyctl" => {
            if x86_64 {
                250
            } else {
                219
            }
        }
        "add_key" => {
            if x86_64 {
                248
            } else {
                217
            }
        }
        "request_key" => {
            if x86_64 {
                249
            } else {
                218
            }
        }
        "io_uring_setup" => 425,
        "io_uring_enter" => 426,
        "io_uring_register" => 427,
        "userfaultfd" => {
            if x86_64 {
                323
            } else {
                282
            }
        }
        "name_to_handle_at" => {
            if x86_64 {
                303
            } else {
                264
            }
        }
        "open_by_handle_at" => {
            if x86_64 {
                304
            } else {
                265
            }
        }
        "reboot" => {
            if x86_64 {
                169
            } else {
                142
            }
        }
        "swapon" => {
            if x86_64 {
                167
            } else {
                224
            }
        }
        "swapoff" => {
            if x86_64 {
                168
            } else {
                225
            }
        }
        "syslog" => {
            if x86_64 {
                103
            } else {
                116
            }
        }
        "acct" => {
            if x86_64 {
                163
            } else {
                89
            }
        }
        "quotactl" => {
            if x86_64 {
                179
            } else {
                60
            }
        }
        "setuid" => {
            if x86_64 {
                105
            } else {
                146
            }
        }
        "setgid" => {
            if x86_64 {
                106
            } else {
                144
            }
        }
        "setreuid" => {
            if x86_64 {
                113
            } else {
                145
            }
        }
        "setregid" => {
            if x86_64 {
                114
            } else {
                143
            }
        }
        "setresuid" => {
            if x86_64 {
                117
            } else {
                147
            }
        }
        "setresgid" => {
            if x86_64 {
                119
            } else {
                149
            }
        }
        "setfsuid" => {
            if x86_64 {
                122
            } else {
                151
            }
        }
        "setfsgid" => {
            if x86_64 {
                123
            } else {
                152
            }
        }
        "personality" => {
            if x86_64 {
                135
            } else {
                92
            }
        }
        _ => return None,
    })
}

/// The architecture this binary was built for.
pub const fn native_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Build the BPF program for an architecture.
///
/// The architecture check comes first and is not optional. Without it, a
/// 32-bit compatibility syscall carries a different number for the same
/// operation, so a filter that blocks `mount` on x86-64 blocks something else
/// entirely when entered through the i386 gate — and lets `mount` through.
pub fn build_filter(arch: u32) -> Vec<SockFilter> {
    let mut prog = Vec::with_capacity(2 + DENIED.len() * 2 + 2);

    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    // Not our architecture: kill, do not fall through to the number checks.
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    for name in DENIED {
        let Some(nr) = syscall_number(name, arch) else { continue };
        // Two instructions per syscall keeps every jump offset at 0 or 1, so
        // the filter cannot outgrow the 8-bit jump field however long the
        // denylist becomes.
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog
}

extern "C" {
    // Declared once for the whole crate. `prctl` is variadic in C, and the
    // arguments must be declared wide enough to carry a pointer — the seccomp
    // call passes one. A `c_uint` declaration would truncate it on 64-bit and
    // hand the kernel half an address.
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
}

/// Set `PR_SET_NO_NEW_PRIVS`.
///
/// Required before an unprivileged process may install a seccomp filter or a
/// Landlock ruleset, and worth having on its own merits: it stops setuid
/// binaries conferring privilege, which closes the `sudo`-shaped escape from
/// inside the sandbox.
pub fn set_no_new_privs() -> Result<(), EnforceError> {
    // SAFETY: a constant option with scalar arguments only; no pointers.
    if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(EnforceError::Rejected {
            stage: "PR_SET_NO_NEW_PRIVS",
            detail: last_os_error(),
        });
    }
    Ok(())
}

/// Install the filter on the current thread. Irreversible.
pub fn apply(_p: &Profile) -> Result<(), EnforceError> {
    let arch = native_arch();
    if arch == 0 {
        return Err(EnforceError::Unsupported("this architecture"));
    }
    let prog = build_filter(arch);

    set_no_new_privs()?;

    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    // SAFETY: `fprog` points at `prog`, which outlives the call. The kernel
    // copies the program during the call and retains nothing.
    let rc = unsafe {
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog as *const SockFprog as c_ulong, 0, 0)
    };
    if rc != 0 {
        return Err(EnforceError::Rejected { stage: "PR_SET_SECCOMP", detail: last_os_error() });
    }
    Ok(())
}

fn last_os_error() -> String {
    std::io::Error::last_os_error().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_denied_syscall_has_a_number_on_both_architectures() {
        // A name with no number is a rule that silently does nothing.
        for name in DENIED {
            assert!(
                syscall_number(name, AUDIT_ARCH_X86_64).is_some(),
                "{name} has no x86_64 number"
            );
            assert!(
                syscall_number(name, AUDIT_ARCH_AARCH64).is_some(),
                "{name} has no aarch64 number"
            );
        }
    }

    #[test]
    fn io_uring_is_blocked() {
        // Called out explicitly because it is the entry whose absence would
        // make the rest of the filter decorative.
        for s in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
            assert!(DENIED.contains(&s), "{s} must be denied");
        }
    }

    #[test]
    fn the_filter_checks_architecture_before_syscall_numbers() {
        let prog = build_filter(AUDIT_ARCH_X86_64);
        assert_eq!(prog[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[0].k, OFF_ARCH, "the arch check must come first");
        assert_eq!(prog[2].code, BPF_RET | BPF_K);
        assert_eq!(prog[2].k, SECCOMP_RET_KILL_PROCESS, "a foreign arch must be killed");
        assert_eq!(prog[3].k, OFF_NR);
    }

    #[test]
    fn the_filter_ends_in_allow() {
        let prog = build_filter(AUDIT_ARCH_AARCH64);
        let last = prog.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn every_jump_offset_fits_the_eight_bit_field() {
        for arch in [AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64] {
            for insn in build_filter(arch) {
                assert!(insn.jt <= 1 && insn.jf <= 1);
            }
        }
    }

    #[test]
    fn the_filter_is_within_the_kernel_instruction_limit() {
        // BPF_MAXINSNS is 4096.
        assert!(build_filter(AUDIT_ARCH_X86_64).len() < 4096);
    }

    #[test]
    fn architecture_numbers_differ_where_they_should() {
        // A regression here would produce a filter that loads cleanly and
        // blocks the wrong syscalls.
        assert_ne!(
            syscall_number("mount", AUDIT_ARCH_X86_64),
            syscall_number("mount", AUDIT_ARCH_AARCH64)
        );
        // io_uring was added after the split, so it shares numbers.
        assert_eq!(
            syscall_number("io_uring_setup", AUDIT_ARCH_X86_64),
            syscall_number("io_uring_setup", AUDIT_ARCH_AARCH64)
        );
    }
}
