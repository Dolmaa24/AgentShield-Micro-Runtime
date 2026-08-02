// vzrunner — a minimal Virtualization.framework host for ephemeral guests.
//
// Rust drives this over argv and stdout rather than binding the Objective-C
// API directly: Virtualization is a Cocoa framework with delegates and a
// run loop, and hand-rolling `objc_msgSend` for it would be a large amount of
// unsafe code to avoid one small Swift file. The workspace's no-dependency
// rule is about not importing unaudited third-party code; a first-party Apple
// framework used through its own language is not that.
//
// Modes:
//   vzrunner probe                 — report whether virtualisation is usable
//   vzrunner validate <config>     — build the VM configuration and validate it
//   vzrunner run <config>          — boot, run one command over vsock, exit
//
// `validate` exists because it is the part that can be checked without a guest
// kernel image. VZVirtualMachineConfiguration.validate() catches most of what
// goes wrong — bad memory sizes, missing files, unsupported device
// combinations — and does it in microseconds.

import Foundation
import Virtualization

// MARK: - Configuration

struct Share: Decodable {
    var tag: String
    var path: String
    var readOnly: Bool
}

struct Config: Decodable {
    var kernel: String
    var initrd: String?
    var cmdline: String
    var cpus: Int
    var memoryMB: UInt64
    var shares: [Share]
    /// Guest vsock port the in-guest agent listens on.
    var vsockPort: UInt32
    /// Shell source to run in the guest.
    var command: String
    var timeoutMs: UInt64
}

struct RunResult: Encodable {
    var exitCode: Int32?
    var timedOut: Bool
    var stdout: String
    var stderr: String
    var bootMs: Double
}

enum RunnerError: Error, CustomStringConvertible {
    case usage(String)
    case config(String)
    case vm(String)

    var description: String {
        switch self {
        case .usage(let m): return "usage: \(m)"
        case .config(let m): return "config: \(m)"
        case .vm(let m): return "vm: \(m)"
        }
    }
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

// MARK: - Building the machine

func buildConfiguration(_ cfg: Config) throws -> VZVirtualMachineConfiguration {
    let vm = VZVirtualMachineConfiguration()

    let kernelURL = URL(fileURLWithPath: cfg.kernel)
    guard FileManager.default.fileExists(atPath: kernelURL.path) else {
        throw RunnerError.config("kernel not found at \(cfg.kernel)")
    }

    let boot = VZLinuxBootLoader(kernelURL: kernelURL)
    boot.commandLine = cfg.cmdline
    if let initrd = cfg.initrd {
        let url = URL(fileURLWithPath: initrd)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw RunnerError.config("initrd not found at \(initrd)")
        }
        boot.initialRamdiskURL = url
    }
    vm.bootLoader = boot

    vm.cpuCount = cfg.cpus
    vm.memorySize = cfg.memoryMB * 1024 * 1024

    // Serial console, so a guest that fails to boot says why instead of
    // hanging silently — the single most useful thing when a guest image is
    // wrong, which it usually is the first several times.
    let console = VZVirtioConsoleDeviceSerialPortConfiguration()
    console.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle.standardInput,
        fileHandleForWriting: FileHandle.standardError
    )
    vm.serialPorts = [console]

    // vsock is the control channel. It needs no guest networking, which means
    // the guest can run with no network interface at all and still be driven.
    vm.socketDevices = [VZVirtioSocketDeviceConfiguration()]

    vm.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    vm.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

    var sharing: [VZDirectorySharingDeviceConfiguration] = []
    for share in cfg.shares {
        let url = URL(fileURLWithPath: share.path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw RunnerError.config("shared directory not found at \(share.path)")
        }
        // The tag is validated separately: an invalid one throws from
        // validate() with a message that does not name the tag.
        do {
            try VZVirtioFileSystemDeviceConfiguration.validateTag(share.tag)
        } catch {
            throw RunnerError.config("invalid share tag \(share.tag): \(error)")
        }
        let device = VZVirtioFileSystemDeviceConfiguration(tag: share.tag)
        device.share = VZSingleDirectoryShare(
            directory: VZSharedDirectory(url: url, readOnly: share.readOnly)
        )
        sharing.append(device)
    }
    vm.directorySharingDevices = sharing

    try vm.validate()
    return vm
}

// MARK: - Delegate

final class Delegate: NSObject, VZVirtualMachineDelegate {
    var onStop: ((Error?) -> Void)?

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        onStop?(nil)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        onStop?(error)
    }
}

// MARK: - Wire protocol
//
// Length-prefixed JSON, both directions: a 4-byte big-endian length followed
// by that many bytes. Framing is explicit because a vsock stream has no
// message boundaries, and "read until EOF" cannot work on a channel that stays
// open for a second command.

func writeFrame(_ fh: FileHandle, _ payload: Data) throws {
    var len = UInt32(payload.count).bigEndian
    var out = Data(bytes: &len, count: 4)
    out.append(payload)
    try fh.write(contentsOf: out)
}

func readFrame(_ fh: FileHandle, timeout: TimeInterval) throws -> Data {
    func readExactly(_ n: Int) throws -> Data {
        var acc = Data()
        let deadline = Date().addingTimeInterval(timeout)
        while acc.count < n {
            if Date() > deadline { throw RunnerError.vm("timed out reading from the guest") }
            guard let chunk = try fh.read(upToCount: n - acc.count), !chunk.isEmpty else {
                throw RunnerError.vm("guest closed the connection")
            }
            acc.append(chunk)
        }
        return acc
    }
    let header = try readExactly(4)
    let len = header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    guard len <= 64 * 1024 * 1024 else {
        throw RunnerError.vm("guest announced an implausible frame of \(len) bytes")
    }
    return try readExactly(Int(len))
}

// MARK: - Modes

func modeProbe() -> Never {
    // `isSupported` is false on Intel Macs without the right hardware and in
    // nested-virtualisation situations; the entitlement is checked separately
    // because a missing one fails at VM creation rather than here.
    let supported = VZVirtualMachine.isSupported
    let payload: [String: Any] = [
        "supported": supported,
        "os": ProcessInfo.processInfo.operatingSystemVersionString,
    ]
    let data = try! JSONSerialization.data(withJSONObject: payload)
    FileHandle.standardOutput.write(data)
    exit(supported ? 0 : 2)
}

func loadConfig(_ path: String) -> Config {
    guard let data = FileManager.default.contents(atPath: path) else {
        fail("cannot read config at \(path)")
    }
    do {
        return try JSONDecoder().decode(Config.self, from: data)
    } catch {
        fail("malformed config: \(error)")
    }
}

func modeValidate(_ path: String) -> Never {
    let cfg = loadConfig(path)
    do {
        _ = try buildConfiguration(cfg)
        FileHandle.standardOutput.write(Data(#"{"valid":true}"#.utf8))
        exit(0)
    } catch {
        let msg = String(describing: error)
        let payload = ["valid": false, "error": msg] as [String: Any]
        let data = (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
        FileHandle.standardOutput.write(data)
        exit(3)
    }
}

func modeRun(_ path: String) -> Never {
    let cfg = loadConfig(path)
    let started = Date()

    let configuration: VZVirtualMachineConfiguration
    do {
        configuration = try buildConfiguration(cfg)
    } catch {
        fail("\(error)")
    }

    let queue = DispatchQueue(label: "shellguard.vz")
    let vm = VZVirtualMachine(configuration: configuration, queue: queue)
    let delegate = Delegate()
    queue.sync { vm.delegate = delegate }

    let bootDone = DispatchSemaphore(value: 0)
    var bootError: Error?
    queue.async {
        vm.start { result in
            if case .failure(let e) = result { bootError = e }
            bootDone.signal()
        }
    }

    let bootTimeout = DispatchTime.now() + .seconds(60)
    guard bootDone.wait(timeout: bootTimeout) == .success else {
        fail("guest did not start within 60s")
    }
    if let e = bootError {
        fail("guest failed to start: \(e)")
    }

    // Connect to the in-guest agent. The guest is still initialising when
    // `start` returns, so this retries rather than assuming the listener is up.
    var connection: VZVirtioSocketConnection?
    let connectDeadline = Date().addingTimeInterval(30)
    while Date() < connectDeadline && connection == nil {
        let sem = DispatchSemaphore(value: 0)
        queue.async {
            guard let socketDevice = vm.socketDevices.first as? VZVirtioSocketDevice else {
                sem.signal()
                return
            }
            socketDevice.connect(toPort: cfg.vsockPort) { result in
                if case .success(let c) = result { connection = c }
                sem.signal()
            }
        }
        _ = sem.wait(timeout: .now() + .seconds(2))
        if connection == nil { usleep(50_000) }
    }

    guard let conn = connection else {
        fail("could not reach the guest agent on vsock port \(cfg.vsockPort)")
    }

    let bootMs = Date().timeIntervalSince(started) * 1000.0
    let fh = FileHandle(fileDescriptor: conn.fileDescriptor, closeOnDealloc: true)

    let request: [String: Any] = [
        "command": cfg.command,
        "timeout_ms": cfg.timeoutMs,
    ]

    var result = RunResult(
        exitCode: nil, timedOut: true, stdout: "", stderr: "", bootMs: bootMs)
    do {
        try writeFrame(fh, try JSONSerialization.data(withJSONObject: request))
        let reply = try readFrame(fh, timeout: TimeInterval(cfg.timeoutMs) / 1000.0 + 5)
        if let obj = try JSONSerialization.jsonObject(with: reply) as? [String: Any] {
            result.exitCode = (obj["exit_code"] as? NSNumber)?.int32Value
            result.timedOut = (obj["timed_out"] as? Bool) ?? false
            result.stdout = (obj["stdout"] as? String) ?? ""
            result.stderr = (obj["stderr"] as? String) ?? ""
        }
    } catch {
        result.stderr = String(describing: error)
    }

    // The guest is ephemeral: stop it rather than reusing it, so nothing the
    // command did can reach the next one.
    let stopped = DispatchSemaphore(value: 0)
    queue.async {
        if vm.canRequestStop {
            try? vm.requestStop()
        }
        stopped.signal()
    }
    _ = stopped.wait(timeout: .now() + .seconds(5))

    let out = (try? JSONEncoder().encode(result)) ?? Data()
    FileHandle.standardOutput.write(out)
    exit(0)
}

// MARK: - Entry

let args = CommandLine.arguments
guard args.count >= 2 else {
    fail("vzrunner <probe|validate|run> [config.json]", code: 64)
}

switch args[1] {
case "probe":
    modeProbe()
case "validate":
    guard args.count >= 3 else { fail("validate needs a config path", code: 64) }
    modeValidate(args[2])
case "run":
    guard args.count >= 3 else { fail("run needs a config path", code: 64) }
    modeRun(args[2])
default:
    fail("unknown mode \(args[1])", code: 64)
}
