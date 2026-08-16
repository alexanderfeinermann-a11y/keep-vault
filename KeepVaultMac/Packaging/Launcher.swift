import AppKit
import CryptoKit
import Darwin
import Foundation
import Security

private let bundleIdentifier = "de.michael-feinermann.keep-vault"
private let coreIdentifier = "de.michael-feinermann.keep-vault.core"
private let supervisorIdentifier = "de.michael-feinermann.keep-vault.supervisor"
private let appleTeamIdentifier = "2T6K9PGS55"
private let coreName = "Keep Vault"
private let launcherName = "Keep Vault Launcher"
private let supervisorName = "Keep Vault Supervisor"
private let handshakeFileDescriptor: Int32 = 198
private let supervisorReadyByte: UInt8 = 0x4B
private let posixSpawnSetExec: Int16 = 0x0040
private let posixSpawnStartSuspended: Int16 = 0x0080
private let hybridMagic = Data("KZVHSIG1".utf8)
private let hybridDomain = Data("KalynaZpaqVault/HybridArtifactSignature/SHA-512/v1\0".utf8)
private let hybridContext = Data("KalynaZpaqVault/HybridArtifactSignature/v1".utf8)
private let maximumHybridSidecarBytes = 64 * 1024
private let rsa4096SignatureBytes = 512
private let mldsa87SignatureBytes = 4627
private let mldsa87PublicKeyBytes = 2592

@_silgen_name("mldsa87_verify")
private func mldsa87Verify(
    _ signature: UnsafePointer<UInt8>,
    _ signatureLength: Int,
    _ message: UnsafePointer<UInt8>,
    _ messageLength: Int,
    _ context: UnsafePointer<UInt8>,
    _ contextLength: Int,
    _ publicKey: UnsafePointer<UInt8>,
    _ publicKeyLength: Int
) -> Int32

@_silgen_name("mldsa87_reference_commit")
private func mldsa87ReferenceCommit() -> UnsafePointer<CChar>?

private struct LauncherFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

private struct OpenedCore {
    let fileDescriptor: Int32
    let device: UInt64
    let inode: UInt64
    let length: Int64
    let digest: Data
}

private struct HybridEnvelope {
    let length: Int64
    let digest: Data
    let certificate: Data
    let rsaSignature: Data
    let mldsaSignature: Data
}

private func fail(_ message: String) -> Never {
    fputs("Keep Vault: \(message)\n", stderr)
    if getenv("SSH_CONNECTION") == nil && getenv("CI") == nil {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        application.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Keep Vault wurde aus Sicherheitsgruenden blockiert"
        alert.informativeText = message
        alert.addButton(withTitle: "Beenden")
        alert.runModal()
    }
    exit(78)
}

private func securityMessage(_ status: OSStatus) -> String {
    if let text = SecCopyErrorMessageString(status, nil) {
        return text as String
    }
    return "Security.framework status \(status)"
}

private func validateStaticCode(at url: URL, requirement requirementText: String, nested: Bool) throws {
    var staticCode: SecStaticCode?
    var status = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode)
    guard status == errSecSuccess, let staticCode else {
        throw LauncherFailure(message: "Apple-Code-Signatur konnte nicht geoeffnet werden: \(securityMessage(status)).")
    }

    var requirement: SecRequirement?
    status = SecRequirementCreateWithString(requirementText as CFString, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        throw LauncherFailure(message: "Die fest eingebundene Apple-Signierrichtlinie ist ungueltig: \(securityMessage(status)).")
    }

    // kSecCSNoNetworkAccess and kSecCSConsiderExpiration are present in the
    // Security headers but are not imported by every Swift SDK overlay.
    var rawFlags = UInt32(kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        | (UInt32(1) << 29)
        | (UInt32(1) << 31)
    if nested {
        rawFlags |= UInt32(kSecCSCheckNestedCode)
    }
    status = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: rawFlags), requirement)
    guard status == errSecSuccess else {
        throw LauncherFailure(message: "Apple-Code-Signatur ist ungueltig: \(securityMessage(status)).")
    }
}

private func pinnedRequirement(identifier: String, cdHashes: [String]) throws -> String {
    guard !cdHashes.isEmpty,
          cdHashes.allSatisfy({ $0.count == 40 && $0.allSatisfy(\.isHexDigit) }) else {
        throw LauncherFailure(message: "Die eingebettete Apple-CDHash-Richtlinie ist ungueltig.")
    }
    let alternatives = cdHashes.map { "cdhash H\"\($0.lowercased())\"" }.joined(separator: " or ")
    return "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeamIdentifier)\" and (\(alternatives))"
}

private func validateDynamicCode(processIdentifier: pid_t, requirementText: String) throws {
    let attributes = [kSecGuestAttributePid: NSNumber(value: processIdentifier)] as CFDictionary
    var code: SecCode?
    var status = SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &code)
    guard status == errSecSuccess, let code else {
        throw LauncherFailure(message: "Der laufende Sicherheits-Supervisor konnte nicht geprueft werden: \(securityMessage(status)).")
    }

    var requirement: SecRequirement?
    status = SecRequirementCreateWithString(requirementText as CFString, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        throw LauncherFailure(message: "Die Supervisor-CDHash-Richtlinie ist ungueltig: \(securityMessage(status)).")
    }
    let rawFlags = UInt32(kSecCSStrictValidate) | (UInt32(1) << 29) | (UInt32(1) << 31)
    status = SecCodeCheckValidity(code, SecCSFlags(rawValue: rawFlags), requirement)
    guard status == errSecSuccess else {
        throw LauncherFailure(message: "Der tatsaechlich gestartete Supervisor stimmt nicht mit seinem CDHash-Pin ueberein: \(securityMessage(status)).")
    }
}

private func openAndHashCore(at path: String, subject: String = "App-Core") throws -> OpenedCore {
    let fileDescriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW_ANY)
    guard fileDescriptor >= 0 else {
        throw LauncherFailure(message: "Der signierte \(subject) kann nicht symlink-sicher geoeffnet werden (errno \(errno)).")
    }

    do {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw LauncherFailure(message: "Der \(subject) kann nicht statisch geprueft werden (errno \(errno)).")
        }
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_size > 0,
              (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 else {
            throw LauncherFailure(message: "Der \(subject) ist kein geschuetztes regulaeres Einzel-Link-Artefakt.")
        }

        var hasher = SHA512()
        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let count = read(fileDescriptor, &buffer, buffer.count)
            if count == 0 {
                break
            }
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw LauncherFailure(message: "Der \(subject) konnte nicht vollstaendig gehasht werden (errno \(errno)).")
            }
            hasher.update(data: Data(buffer[0..<count]))
        }
        buffer.resetBytes(in: buffer.indices)

        var after = stat()
        guard fstat(fileDescriptor, &after) == 0,
              after.st_dev == info.st_dev,
              after.st_ino == info.st_ino,
              after.st_size == info.st_size,
              after.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec else {
            throw LauncherFailure(message: "Der App-Core wurde waehrend der Pruefung veraendert.")
        }

        return OpenedCore(
            fileDescriptor: fileDescriptor,
            device: UInt64(info.st_dev),
            inode: UInt64(info.st_ino),
            length: info.st_size,
            digest: Data(hasher.finalize()))
    } catch {
        close(fileDescriptor)
        throw error
    }
}

private func readRegularFile(at path: String, maximumBytes: Int) throws -> Data {
    let fileDescriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW_ANY)
    guard fileDescriptor >= 0 else {
        throw LauncherFailure(message: "Eine erforderliche Integritaetsdatei fehlt oder ist ein Symlink: \(URL(fileURLWithPath: path).lastPathComponent).")
    }
    defer { close(fileDescriptor) }

    var info = stat()
    guard fstat(fileDescriptor, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_nlink == 1,
          info.st_size > 0,
          info.st_size <= maximumBytes,
          (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 else {
        throw LauncherFailure(message: "Eine Integritaetsdatei besitzt unzulaessige Dateieigenschaften.")
    }

    var result = Data(count: Int(info.st_size))
    var offset = 0
    try result.withUnsafeMutableBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else {
            throw LauncherFailure(message: "Eine Integritaetsdatei konnte nicht gelesen werden.")
        }
        while offset < rawBuffer.count {
            let count = read(fileDescriptor, base.advanced(by: offset), rawBuffer.count - offset)
            if count < 0 && errno == EINTR {
                continue
            }
            guard count > 0 else {
                throw LauncherFailure(message: "Eine Integritaetsdatei ist waehrend des Lesens abgebrochen.")
            }
            offset += count
        }
    }
    return result
}

private func littleEndianInt32(_ data: Data, at offset: inout Int) throws -> Int {
    guard offset <= data.count - 4 else {
        throw LauncherFailure(message: "Die hybride Signatur ist abgeschnitten.")
    }
    let value = Int(data[offset])
        | (Int(data[offset + 1]) << 8)
        | (Int(data[offset + 2]) << 16)
        | (Int(data[offset + 3]) << 24)
    offset += 4
    return value
}

private func littleEndianInt64(_ data: Data, at offset: inout Int) throws -> Int64 {
    guard offset <= data.count - 8 else {
        throw LauncherFailure(message: "Die hybride Signatur ist abgeschnitten.")
    }
    var value: UInt64 = 0
    for byteIndex in 0..<8 {
        value |= UInt64(data[offset + byteIndex]) << UInt64(byteIndex * 8)
    }
    offset += 8
    guard value <= UInt64(Int64.max) else {
        throw LauncherFailure(message: "Die hybride Signatur enthaelt eine ungueltige Dateilaenge.")
    }
    return Int64(value)
}

private func appendLittleEndianInt64(_ value: Int64, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func parseHybridEnvelope(_ encoded: Data) throws -> HybridEnvelope {
    let fixedBytes = hybridMagic.count + 4 + 8 + 64 + 12
    guard encoded.count >= fixedBytes,
          constantTimeEqual(Data(encoded.prefix(hybridMagic.count)), hybridMagic) else {
        throw LauncherFailure(message: "Die hybride Signatur besitzt keinen gueltigen Header.")
    }

    var offset = hybridMagic.count
    guard try littleEndianInt32(encoded, at: &offset) == 1 else {
        throw LauncherFailure(message: "Die hybride Signaturversion wird nicht unterstuetzt.")
    }
    let length = try littleEndianInt64(encoded, at: &offset)
    let digest = encoded.subdata(in: offset..<(offset + 64))
    offset += 64
    let certificateLength = try littleEndianInt32(encoded, at: &offset)
    let rsaLength = try littleEndianInt32(encoded, at: &offset)
    let mldsaLength = try littleEndianInt32(encoded, at: &offset)
    guard certificateLength > 0,
          certificateLength <= 32 * 1024,
          rsaLength == rsa4096SignatureBytes,
          mldsaLength == mldsa87SignatureBytes,
          offset <= encoded.count - certificateLength - rsaLength - mldsaLength,
          offset + certificateLength + rsaLength + mldsaLength == encoded.count else {
        throw LauncherFailure(message: "Die hybride Signatur besitzt ungueltige Komponentenlaengen.")
    }

    let certificate = encoded.subdata(in: offset..<(offset + certificateLength))
    offset += certificateLength
    let rsa = encoded.subdata(in: offset..<(offset + rsaLength))
    offset += rsaLength
    let mldsa = encoded.subdata(in: offset..<(offset + mldsaLength))
    return HybridEnvelope(length: length, digest: digest, certificate: certificate, rsaSignature: rsa, mldsaSignature: mldsa)
}

private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for index in left.indices {
        difference |= left[index] ^ right[index]
    }
    return difference == 0
}

private func verifyHybridCore(_ openedCore: OpenedCore, signaturePath: String, subject: String = "App-Core") throws {
    guard KeepVaultHybridPins.rsaCertificateSha256.count == SHA256.byteCount,
          KeepVaultHybridPins.mldsaPublicKey.count == mldsa87PublicKeyBytes else {
        throw LauncherFailure(message: "Die Launcher-Signierrichtlinie besitzt ungueltige Schluessellaengen.")
    }
    guard let commitPointer = mldsa87ReferenceCommit(),
          String(cString: commitPointer) == "pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be" else {
        throw LauncherFailure(message: "Der fest eingebundene ML-DSA-87-Referenzcode besitzt eine unerwartete Revision.")
    }

    let encoded = try readRegularFile(at: signaturePath, maximumBytes: maximumHybridSidecarBytes)
    let envelope = try parseHybridEnvelope(encoded)
    guard envelope.length == openedCore.length,
          constantTimeEqual(envelope.digest, openedCore.digest) else {
        throw LauncherFailure(message: "Die hybride Signatur ist nicht an diesen \(subject) gebunden.")
    }

    let actualCertificatePin = Data(SHA256.hash(data: envelope.certificate))
    guard constantTimeEqual(actualCertificatePin, Data(KeepVaultHybridPins.rsaCertificateSha256)) else {
        throw LauncherFailure(message: "Das RSA-4096-Signierzertifikat stimmt nicht mit dem Launcher-Pin ueberein.")
    }
    guard let certificate = SecCertificateCreateWithData(nil, envelope.certificate as CFData),
          let rsaKey = SecCertificateCopyKey(certificate),
          let attributes = SecKeyCopyAttributes(rsaKey) as? [CFString: Any],
          let bits = attributes[kSecAttrKeySizeInBits] as? Int,
          bits == 4096 else {
        throw LauncherFailure(message: "Die hybride Signatur enthaelt kein RSA-4096-Zertifikat.")
    }

    var payload = hybridDomain
    appendLittleEndianInt64(openedCore.length, to: &payload)
    payload.append(openedCore.digest)
    var rsaError: Unmanaged<CFError>?
    guard SecKeyVerifySignature(
        rsaKey,
        .rsaSignatureMessagePSSSHA512,
        payload as CFData,
        envelope.rsaSignature as CFData,
        &rsaError) else {
        let reason = rsaError?.takeRetainedValue().localizedDescription ?? "unbekannter Fehler"
        throw LauncherFailure(message: "RSA-PSS/SHA-512-Signatur (\(subject)) ist ungueltig: \(reason).")
    }

    let publicKey = Data(KeepVaultHybridPins.mldsaPublicKey)
    let referenceResult = envelope.mldsaSignature.withUnsafeBytes { signatureBytes in
        payload.withUnsafeBytes { payloadBytes in
            hybridContext.withUnsafeBytes { contextBytes in
                publicKey.withUnsafeBytes { publicKeyBytes in
                    mldsa87Verify(
                        signatureBytes.bindMemory(to: UInt8.self).baseAddress!,
                        signatureBytes.count,
                        payloadBytes.bindMemory(to: UInt8.self).baseAddress!,
                        payloadBytes.count,
                        contextBytes.bindMemory(to: UInt8.self).baseAddress!,
                        contextBytes.count,
                        publicKeyBytes.bindMemory(to: UInt8.self).baseAddress!,
                        publicKeyBytes.count)
                }
            }
        }
    }
    guard referenceResult == 0 else {
        throw LauncherFailure(message: "ML-DSA-87-Signatur (\(subject)) ist ungueltig.")
    }
}

private func ensurePathStillNamesCore(_ openedCore: OpenedCore, path: String) throws {
    var current = stat()
    guard lstat(path, &current) == 0,
          (current.st_mode & S_IFMT) == S_IFREG,
          UInt64(current.st_dev) == openedCore.device,
          UInt64(current.st_ino) == openedCore.inode,
          current.st_size == openedCore.length else {
        throw LauncherFailure(message: "Der App-Core wurde nach der Signaturpruefung ausgetauscht.")
    }
}

private func setCloseOnExec(_ descriptor: Int32) throws {
    let current = fcntl(descriptor, F_GETFD)
    guard current >= 0, fcntl(descriptor, F_SETFD, current | FD_CLOEXEC) == 0 else {
        throw LauncherFailure(message: "Ein Supervisor-Dateideskriptor konnte nicht geschuetzt werden (errno \(errno)).")
    }
}

private func waitForSupervisorReady(_ descriptor: Int32) throws {
    var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    var pollResult: Int32
    repeat {
        pollResult = poll(&pollDescriptor, 1, 5_000)
    } while pollResult < 0 && errno == EINTR
    guard pollResult == 1, (pollDescriptor.revents & Int16(POLLIN)) != 0 else {
        throw LauncherFailure(message: "Der Sicherheits-Supervisor wurde nicht rechtzeitig bereit.")
    }

    var byte: UInt8 = 0
    var readResult: Int
    repeat {
        readResult = withUnsafeMutablePointer(to: &byte) { read(descriptor, $0, 1) }
    } while readResult < 0 && errno == EINTR
    guard readResult == 1, byte == supervisorReadyByte else {
        throw LauncherFailure(message: "Der Sicherheits-Supervisor lieferte keine gueltige Bereitschaftsbestaetigung.")
    }
}

private func spawnSuspendedSupervisor(at path: String) throws -> (pid_t, Int32) {
    var descriptors = [Int32](repeating: -1, count: 2)
    let pipeResult = descriptors.withUnsafeMutableBufferPointer { buffer in
        pipe(buffer.baseAddress!)
    }
    guard pipeResult == 0 else {
        throw LauncherFailure(message: "Der Supervisor-Kontrollkanal konnte nicht erzeugt werden (errno \(errno)).")
    }
    let readDescriptor = descriptors[0]
    let writeDescriptor = descriptors[1]

    do {
        try setCloseOnExec(readDescriptor)
        try setCloseOnExec(writeDescriptor)
        var actions: posix_spawn_file_actions_t? = nil
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0 else {
            throw LauncherFailure(message: "Supervisor-Startattribute konnten nicht initialisiert werden.")
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }

        guard posix_spawn_file_actions_adddup2(&actions, writeDescriptor, handshakeFileDescriptor) == 0,
              posix_spawn_file_actions_addclose(&actions, readDescriptor) == 0 else {
            throw LauncherFailure(message: "Supervisor-Dateideskriptoren konnten nicht gebunden werden.")
        }
        if writeDescriptor != handshakeFileDescriptor {
            guard posix_spawn_file_actions_addclose(&actions, writeDescriptor) == 0 else {
                throw LauncherFailure(message: "Der urspruengliche Supervisor-Dateideskriptor konnte nicht geschlossen werden.")
            }
        }
        let flags = posixSpawnStartSuspended
        guard posix_spawnattr_setflags(&attributes, flags) == 0 else {
            throw LauncherFailure(message: "Der Supervisor konnte nicht auf suspendierten Start festgelegt werden.")
        }

        var arguments = [strdup(path), nil]
        defer { free(arguments[0]) }
        var processIdentifier: pid_t = 0
        let spawnStatus = posix_spawn(
            &processIdentifier,
            path,
            &actions,
            &attributes,
            &arguments,
            environ)
        guard spawnStatus == 0, processIdentifier > 1 else {
            throw LauncherFailure(message: "Der Sicherheits-Supervisor konnte nicht suspendiert gestartet werden (Fehler \(spawnStatus)).")
        }
        close(writeDescriptor)
        return (processIdentifier, readDescriptor)
    } catch {
        close(readDescriptor)
        close(writeDescriptor)
        throw error
    }
}

private func replaceWithSuspendedCore(at path: String, openedCore: OpenedCore) throws -> Never {
    try ensurePathStillNamesCore(openedCore, path: path)

    var arguments = [path]
    if CommandLine.arguments.count > 1 {
        arguments.append(contentsOf: CommandLine.arguments.dropFirst())
    }
    var cArguments = arguments.map { strdup($0) }
    defer { cArguments.forEach { free($0) } }
    cArguments.append(nil)

    var attributes: posix_spawnattr_t? = nil
    guard posix_spawnattr_init(&attributes) == 0 else {
        throw LauncherFailure(message: "Core-Startattribute konnten nicht initialisiert werden.")
    }
    defer { posix_spawnattr_destroy(&attributes) }
    let flags = posixSpawnSetExec | posixSpawnStartSuspended
    guard posix_spawnattr_setflags(&attributes, flags) == 0 else {
        throw LauncherFailure(message: "Der Core konnte nicht auf suspendierten SETEXEC-Start festgelegt werden.")
    }

    var ignoredProcessIdentifier: pid_t = 0
    let spawnStatus = posix_spawn(
        &ignoredProcessIdentifier,
        path,
        nil,
        &attributes,
        &cArguments,
        environ)
    throw LauncherFailure(message: "Der gepruefte App-Core konnte nicht als suspendierter Prozess eingesetzt werden (Fehler \(spawnStatus)).")
}

@main
private enum KeepVaultLauncher {
    static func main() {
        do {
            let bundleURL = Bundle.main.bundleURL.standardizedFileURL
            guard bundleURL.pathExtension == "app",
                  bundleURL.resolvingSymlinksInPath().standardizedFileURL.path == bundleURL.path else {
                throw LauncherFailure(message: "Das App-Bundle darf nicht ueber symbolische Links gestartet werden.")
            }

            let outerRequirement = "identifier \"\(bundleIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeamIdentifier)\""
            try validateStaticCode(at: bundleURL, requirement: outerRequirement, nested: true)

            let coreURL = bundleURL.appendingPathComponent("Contents/MacOS/\(coreName)", isDirectory: false)
            let coreRequirement = "identifier \"\(coreIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeamIdentifier)\""
            try validateStaticCode(at: coreURL, requirement: coreRequirement, nested: false)

            let supervisorURL = bundleURL.appendingPathComponent("Contents/MacOS/\(supervisorName)", isDirectory: false)
            let supervisorStaticRequirement = "identifier \"\(supervisorIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeamIdentifier)\""
            let supervisorDynamicRequirement = try pinnedRequirement(
                identifier: supervisorIdentifier,
                cdHashes: KeepVaultSupervisorApplePins.cdHashes)
            try validateStaticCode(at: supervisorURL, requirement: supervisorStaticRequirement, nested: false)

            // Contents/MacOS may only hold Mach-O executables; codesign refuses
            // to seal a bundle carrying other payload there. The detached
            // hybrid signatures therefore live under Contents/Resources,
            // mirroring the layout below Contents/MacOS.
            let coreSignatureURL = bundleURL.appendingPathComponent(
                "Contents/Resources/HybridSignatures/\(coreName).khsig",
                isDirectory: false)

            // The supervisor is checked against the same post-quantum pair as
            // everything else. Its Apple signature and its compiled-in cdhash
            // pin are both anchored in RSA and ECDSA, so on their own they would
            // leave this one process resting on assumptions the rest of the app
            // deliberately does not make.
            let supervisorSignatureURL = bundleURL.appendingPathComponent(
                "Contents/Resources/HybridSignatures/\(supervisorName).khsig",
                isDirectory: false)
            let openedSupervisor = try openAndHashCore(at: supervisorURL.path, subject: "Supervisor")
            do {
                try verifyHybridCore(
                    openedSupervisor,
                    signaturePath: supervisorSignatureURL.path,
                    subject: "Supervisor")
            } catch {
                close(openedSupervisor.fileDescriptor)
                throw error
            }
            close(openedSupervisor.fileDescriptor)

            // The launcher is the bundle's main executable, so codesign writes
            // the bundle seal into this very file: a hybrid signature over its
            // own bytes cannot live inside the bundle, because adding it would
            // change the seal and invalidate itself. It therefore sits beside
            // the app, is published alongside the release, and is checked here
            // in addition to Apple's signature — closing the one gap where a
            // component was covered by Apple's signature alone.
            let selfSignatureURL = bundleURL
                .deletingLastPathComponent()
                .appendingPathComponent(bundleURL.lastPathComponent + ".launcher.khsig", isDirectory: false)
            let launcherURL = bundleURL.appendingPathComponent("Contents/MacOS/\(launcherName)", isDirectory: false)
            let openedLauncher = try openAndHashCore(at: launcherURL.path, subject: "Launcher")
            do {
                try verifyHybridCore(openedLauncher, signaturePath: selfSignatureURL.path, subject: "Launcher")
            } catch {
                close(openedLauncher.fileDescriptor)
                let detail = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                throw LauncherFailure(message:
                    "Die duale Signatur des Launchers konnte nicht geprueft werden.\n\n"
                    + "Grund: \(detail)\n\n"
                    + "Die Signatur liegt als \"\(selfSignatureURL.lastPathComponent)\" direkt neben der App "
                    + "und gehoert zwingend dazu. Wurde die App ohne diese Dateien verschoben oder kopiert, "
                    + "installieren Sie sie bitte erneut mit \"Install-KeepVault-macOS.sh\" bzw. entpacken Sie "
                    + "das Release vollstaendig. Andernfalls wurde die App veraendert und darf nicht "
                    + "gestartet werden.")
            }
            close(openedLauncher.fileDescriptor)

            let openedCore = try openAndHashCore(at: coreURL.path)
            do {
                try verifyHybridCore(openedCore, signaturePath: coreSignatureURL.path)
                let (supervisorProcess, readyDescriptor) = try spawnSuspendedSupervisor(at: supervisorURL.path)
                do {
                    try validateDynamicCode(
                        processIdentifier: supervisorProcess,
                        requirementText: supervisorDynamicRequirement)
                    guard kill(supervisorProcess, SIGCONT) == 0 else {
                        throw LauncherFailure(message: "Der gepruefte Supervisor konnte nicht fortgesetzt werden (errno \(errno)).")
                    }
                    try waitForSupervisorReady(readyDescriptor)
                    close(readyDescriptor)
                    try replaceWithSuspendedCore(at: coreURL.path, openedCore: openedCore)
                } catch {
                    close(readyDescriptor)
                    _ = kill(supervisorProcess, SIGKILL)
                    _ = waitpid(supervisorProcess, nil, 0)
                    throw error
                }
            } catch {
                close(openedCore.fileDescriptor)
                throw error
            }
        } catch {
            fail((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
    }
}
