import Darwin
import Dispatch
import Foundation
import Virtualization

private let bridgeReadDeadlineSeconds = 60
private let udsConnectDeadlineSeconds = 10.0
private var retainedTermSignal: DispatchSourceSignal?
private var retainedIntSignal: DispatchSourceSignal?
private var retainedParentWatch: DispatchSourceTimer?

private func stderrLine(_ line: String) {
    if let data = (line + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

private func fatal(_ message: String) -> Never {
    stderrLine("KIRBY_VZ_ERROR \(message)")
    exit(1)
}

private struct HelperArgs {
    let kernel: String
    let rootfs: String
    let uds: String
    let gatewayPort: UInt32
    let cpuCount: Int
    let memoryMib: UInt64
    let workload: String?
    // Hidden diagnostic hook for the VZ dead-fd probe. Normal boots leave this nil.
    let probeStopVmAfterReadyMs: Int?

    static func parse(_ argv: [String]) -> HelperArgs {
        var values: [String: String] = [:]
        var iterator = argv.dropFirst().makeIterator()
        while let flag = iterator.next() {
            guard flag.hasPrefix("--") else {
                fatal("unexpected argument: \(flag)")
            }
            guard let value = iterator.next() else {
                fatal("missing value for \(flag)")
            }
            values[String(flag.dropFirst(2))] = value
        }

        guard let kernel = values["kernel"] else { fatal("missing --kernel") }
        guard let rootfs = values["rootfs"] else { fatal("missing --rootfs") }
        guard let uds = values["gateway-uds"] else { fatal("missing --gateway-uds") }
        guard let portRaw = values["gateway-port"], let gatewayPort = UInt32(portRaw) else {
            fatal("missing or invalid --gateway-port")
        }
        guard let cpuRaw = values["cpus"], let cpuCount = Int(cpuRaw), cpuCount > 0 else {
            fatal("missing or invalid --cpus")
        }
        guard let memRaw = values["memory-mib"], let memoryMib = UInt64(memRaw), memoryMib > 0 else {
            fatal("missing or invalid --memory-mib")
        }

        return HelperArgs(
            kernel: kernel,
            rootfs: rootfs,
            uds: uds,
            gatewayPort: gatewayPort,
            cpuCount: cpuCount,
            memoryMib: memoryMib,
            workload: values["workload"],
            probeStopVmAfterReadyMs: values["probe-stop-vm-after-ready-ms"].flatMap(Int.init)
        )
    }
}

private func retryingUnixConnect(path: String) -> Int32 {
    let deadline = Date().addingTimeInterval(udsConnectDeadlineSeconds)
    var lastErrno: Int32 = 0
    while Date() < deadline {
        let fd = connectUnix(path: path)
        if fd >= 0 {
            return fd
        }
        lastErrno = errno
        usleep(100_000)
    }
    stderrLine("KIRBY_VZ_BRIDGE_ERROR uds_connect_failed path=\(path) errno=\(lastErrno)")
    return -1
}

private func connectUnix(path: String) -> Int32 {
    let maxPathLength = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
    guard path.utf8.count < maxPathLength else {
        errno = ENAMETOOLONG
        return -1
    }

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        return -1
    }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let copied = path.withCString { src in
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: maxPathLength) { dst in
                strncpy(dst, src, maxPathLength - 1)
            }
        }
    }
    _ = copied

    let len = socklen_t(MemoryLayout<sa_family_t>.size + path.utf8.count + 1)
    let rc = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
            Darwin.connect(fd, sockaddrPtr, len)
        }
    }
    if rc == 0 {
        return fd
    }

    let savedErrno = errno
    close(fd)
    errno = savedErrno
    return -1
}

private func setReadDeadline(fd: Int32, seconds: Int) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    _ = withUnsafePointer(to: &timeout) { ptr in
        ptr.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<timeval>.size) { raw in
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, raw, socklen_t(MemoryLayout<timeval>.size))
        }
    }
}

private func pumpBytes(from src: Int32, to dst: Int32, label: String) {
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let n = buffer.withUnsafeMutableBytes { raw in
            Darwin.read(src, raw.baseAddress, raw.count)
        }
        if n > 0 {
            if !writeAll(fd: dst, bytes: buffer, count: n) {
                break
            }
            continue
        }
        if n == 0 {
            break
        }
        if errno == EINTR {
            continue
        }
        if errno == EAGAIN || errno == EWOULDBLOCK {
            stderrLine("KIRBY_VZ_BRIDGE_TIMEOUT direction=\(label)")
            break
        }
        if errno == EBADF {
            break
        }
        stderrLine("KIRBY_VZ_BRIDGE_ERROR direction=\(label) errno=\(errno)")
        break
    }
    shutdown(dst, SHUT_WR)
}

private func writeAll(fd: Int32, bytes: [UInt8], count: Int) -> Bool {
    var written = 0
    while written < count {
        let n = bytes.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return Darwin.write(fd, base.advanced(by: written), count - written)
        }
        if n > 0 {
            written += n
            continue
        }
        if n == 0 {
            return false
        }
        if errno == EINTR {
            continue
        }
        if errno == EAGAIN || errno == EWOULDBLOCK {
            usleep(1_000)
            continue
        }
        return false
    }
    return true
}

private final class ActiveBridge {
    let id: UUID
    private let connection: VZVirtioSocketConnection
    private let udsFd: Int32
    private let vzFd: Int32

    init(id: UUID, connection: VZVirtioSocketConnection, udsFd: Int32) {
        self.id = id
        self.connection = connection
        self.udsFd = udsFd
        self.vzFd = connection.fileDescriptor
    }

    func start(onClose: @escaping () -> Void) {
        setReadDeadline(fd: vzFd, seconds: bridgeReadDeadlineSeconds)
        setReadDeadline(fd: udsFd, seconds: bridgeReadDeadlineSeconds)

        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            pumpBytes(from: self.vzFd, to: self.udsFd, label: "vz_to_uds")
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            pumpBytes(from: self.udsFd, to: self.vzFd, label: "uds_to_vz")
            group.leave()
        }
        group.notify(queue: .global(qos: .utility)) {
            self.close()
            stderrLine("KIRBY_VZ_BRIDGE_CLOSED id=\(self.id.uuidString)")
            onClose()
        }
    }

    func close() {
        connection.close()
        Darwin.close(udsFd)
    }

    deinit {
        close()
    }
}

private final class SocketBridge: NSObject, VZVirtioSocketListenerDelegate {
    private let udsPath: String
    private let lock = DispatchQueue(label: "kirby.vz.bridge.lock")
    private var active: [UUID: ActiveBridge] = [:]

    init(udsPath: String) {
        self.udsPath = udsPath
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        stderrLine(
            "KIRBY_VZ_ACCEPT source_port=\(connection.sourcePort) destination_port=\(connection.destinationPort)"
        )

        let udsFd = retryingUnixConnect(path: udsPath)
        if udsFd < 0 {
            connection.close()
            return true
        }

        let id = UUID()
        let bridge = ActiveBridge(id: id, connection: connection, udsFd: udsFd)
        lock.sync {
            active[id] = bridge
        }
        bridge.start { [weak self] in
            self?.lock.async {
                self?.active[id] = nil
            }
        }
        return true
    }

    func closeAll() {
        lock.sync {
            for bridge in active.values {
                bridge.close()
            }
            active.removeAll()
        }
    }
}

private final class VmController: NSObject, VZVirtualMachineDelegate {
    private let vm: VZVirtualMachine
    private let bridge: SocketBridge
    private let gatewayPort: UInt32
    private let probeStopVmAfterReadyMs: Int?
    private var listener: VZVirtioSocketListener?
    private var stopping = false

    init(
        vm: VZVirtualMachine,
        bridge: SocketBridge,
        gatewayPort: UInt32,
        probeStopVmAfterReadyMs: Int?
    ) {
        self.vm = vm
        self.bridge = bridge
        self.gatewayPort = gatewayPort
        self.probeStopVmAfterReadyMs = probeStopVmAfterReadyMs
        super.init()
    }

    func start() {
        vm.start { result in
            if case .failure(let error) = result {
                fatal("vm_start_failed \(error)")
            }
            guard let socketDevice = self.vm.socketDevices.compactMap({ $0 as? VZVirtioSocketDevice }).first else {
                fatal("vm_started_without_virtio_socket_device")
            }

            let listener = VZVirtioSocketListener()
            listener.delegate = self.bridge
            socketDevice.setSocketListener(listener, forPort: self.gatewayPort)
            self.listener = listener

            stderrLine(
                "KIRBY_VZ_READY pid=\(getpid()) port=\(self.gatewayPort) state=\(self.vm.state.rawValue)"
            )
            if let ms = self.probeStopVmAfterReadyMs {
                stderrLine("KIRBY_VZ_PROBE_STOP_VM_SCHEDULED after_ready_ms=\(ms)")
                DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(ms)) {
                    self.probeStopVmAndKeepHelperAlive()
                }
            }
        }
    }

    func probeStopVmAndKeepHelperAlive() {
        stderrLine("KIRBY_VZ_PROBE_STOP_VM_BEGIN state=\(vm.state.rawValue)")
        guard vm.canStop else {
            stderrLine("KIRBY_VZ_PROBE_STOP_VM_SKIPPED can_stop=false state=\(vm.state.rawValue)")
            return
        }
        vm.stop { error in
            if let error {
                stderrLine("KIRBY_VZ_PROBE_STOP_VM_ERROR \(error)")
            } else {
                stderrLine("KIRBY_VZ_PROBE_STOP_VM_DONE state=\(self.vm.state.rawValue)")
            }
        }
    }

    func stopAndExit(code: Int32) {
        if stopping {
            return
        }
        stopping = true
        bridge.closeAll()

        guard vm.canStop else {
            exit(code)
        }
        vm.stop { error in
            if let error {
                stderrLine("KIRBY_VZ_STOP_ERROR \(error)")
            }
            exit(code)
        }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        stderrLine("KIRBY_VZ_GUEST_STOPPED")
        if probeStopVmAfterReadyMs != nil {
            return
        }
        stopAndExit(code: 0)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        stderrLine("KIRBY_VZ_STOPPED_WITH_ERROR \(error)")
        if probeStopVmAfterReadyMs != nil {
            return
        }
        stopAndExit(code: 1)
    }
}

private func makeConfiguration(args: HelperArgs) -> VZVirtualMachineConfiguration {
    let config = VZVirtualMachineConfiguration()
    config.cpuCount = args.cpuCount
    config.memorySize = args.memoryMib * 1024 * 1024

    let bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: args.kernel))
    var commandLine = "console=ttyAMA0 reboot=k panic=1 root=/dev/vda ro init=/init kirby.gateway_port=\(args.gatewayPort)"
    if let workload = args.workload {
        commandLine += " kirby.workload=\(workload)"
    }
    bootLoader.commandLine = commandLine
    config.bootLoader = bootLoader

    do {
        let attachment = try VZDiskImageStorageDeviceAttachment(
            url: URL(fileURLWithPath: args.rootfs),
            readOnly: true
        )
        config.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
    } catch {
        fatal("rootfs_attachment_failed \(error)")
    }

    config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: nil,
        fileHandleForWriting: FileHandle.standardOutput
    )
    config.serialPorts = [serial]

    do {
        try config.validate()
    } catch {
        fatal("config_validation_failed \(error)")
    }
    return config
}

private func installSignalHandlers(controller: VmController, parentPid: pid_t) {
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)

    let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    term.setEventHandler {
        stderrLine("KIRBY_VZ_SIGNAL signal=TERM")
        controller.stopAndExit(code: 0)
    }
    term.resume()
    retainedTermSignal = term

    let int = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    int.setEventHandler {
        stderrLine("KIRBY_VZ_SIGNAL signal=INT")
        controller.stopAndExit(code: 0)
    }
    int.resume()
    retainedIntSignal = int

    let parentWatch = DispatchSource.makeTimerSource(queue: .main)
    parentWatch.schedule(deadline: .now() + 1.0, repeating: 1.0)
    parentWatch.setEventHandler {
        if getppid() != parentPid {
            stderrLine("KIRBY_VZ_PARENT_GONE original_ppid=\(parentPid) current_ppid=\(getppid())")
            controller.stopAndExit(code: 1)
        }
    }
    parentWatch.resume()
    retainedParentWatch = parentWatch
}

private let args = HelperArgs.parse(CommandLine.arguments)
private let parentPid = getppid()
private let bridge = SocketBridge(udsPath: args.uds)
private let config = makeConfiguration(args: args)
private let vm = VZVirtualMachine(configuration: config)
private let controller = VmController(
    vm: vm,
    bridge: bridge,
    gatewayPort: args.gatewayPort,
    probeStopVmAfterReadyMs: args.probeStopVmAfterReadyMs
)
vm.delegate = controller
installSignalHandlers(controller: controller, parentPid: parentPid)
controller.start()
dispatchMain()
