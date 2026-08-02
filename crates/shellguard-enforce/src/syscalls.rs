//! The syscalls a confined command is refused, by name.
//!
//! Deliberately platform-independent. The Linux backend turns these into
//! numbers for a seccomp-BPF filter; the gVisor backend turns the same list
//! into an OCI seccomp profile. One list, so the two cannot drift apart and
//! quietly protect against different things.

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
