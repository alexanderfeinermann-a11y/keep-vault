import Darwin
import Foundation
import Security

private let bundleIdentifier = "de.michael-feinermann.keep-vault"
private let coreIdentifier = "de.michael-feinermann.keep-vault.core"
private let appleTeamIdentifier = "2T6K9PGS55"
private let handshakeFileDescriptor: Int32 = 198
private let supervisorReadyByte: UInt8 = 0x4B
private let maximumTransitionAttempts = 1_000
private let transitionDelayMicroseconds: useconds_t = 10_000

private struct SupervisorFailure: Error {
    let message: String
}

private func securityMessage(_ status: OSStatus) -> String {
    if let text = SecCopyErrorMessageString(status, nil) {
        return text as String
    }
    return "Security.framework status \(status)"
}

private func requirementText(identifier: String, cdHashes: [String]? = nil) throws -> String {
    var text = "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeamIdentifier)\""
    if let cdHashes {
        guard !cdHashes.isEmpty,
              cdHashes.allSatisfy({ $0.count == 40 && $0.allSatisfy(\.isHexDigit) }) else {
            throw SupervisorFailure(message: "Compiled Apple CDHash policy is invalid.")
        }
        let alternatives = cdHashes.map { "cdhash H\"\($0.lowercased())\"" }.joined(separator: " or ")
        text += " and (\(alternatives))"
    }
    return text
}

private func dynamicCode(for processIdentifier: pid_t) throws -> SecCode {
    let attributes = [kSecGuestAttributePid: NSNumber(value: processIdentifier)] as CFDictionary
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &code)
    guard status == errSecSuccess, let code else {
        throw SupervisorFailure(message: "Unable to obtain dynamic Apple code for PID \(processIdentifier): \(securityMessage(status)).")
    }
    return code
}

private func compiledRequirement(_ text: String) throws -> SecRequirement {
    var requirement: SecRequirement?
    let status = SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
        throw SupervisorFailure(message: "Compiled Apple requirement is invalid: \(securityMessage(status)).")
    }
    return requirement
}

private func validateDynamicCode(_ code: SecCode, requirementText: String) throws {
    let requirement = try compiledRequirement(requirementText)
    let rawFlags = UInt32(kSecCSStrictValidate) | (UInt32(1) << 29) | (UInt32(1) << 31)
    let status = SecCodeCheckValidity(code, SecCSFlags(rawValue: rawFlags), requirement)
    guard status == errSecSuccess else {
        throw SupervisorFailure(message: "Dynamic Apple code did not satisfy its pinned requirement: \(securityMessage(status)).")
    }
}

private func dynamicCodeSatisfies(_ code: SecCode, requirementText: String) -> Bool {
    guard let requirement = try? compiledRequirement(requirementText) else {
        return false
    }
    let rawFlags = UInt32(kSecCSStrictValidate) | (UInt32(1) << 29) | (UInt32(1) << 31)
    return SecCodeCheckValidity(code, SecCSFlags(rawValue: rawFlags), requirement) == errSecSuccess
}

private func writeReadyByte() throws {
    var byte = supervisorReadyByte
    while true {
        let count = withUnsafePointer(to: &byte) { write(handshakeFileDescriptor, $0, 1) }
        if count == 1 {
            close(handshakeFileDescriptor)
            return
        }
        if count < 0 && errno == EINTR {
            continue
        }
        throw SupervisorFailure(message: "Unable to acknowledge supervisor readiness (errno \(errno)).")
    }
}

private func terminateTarget(_ processIdentifier: pid_t, reason: String) -> Never {
    if processIdentifier > 1 {
        _ = kill(processIdentifier, SIGKILL)
    }
    fputs("Keep Vault Supervisor: \(reason)\n", stderr)
    _exit(78)
}

@main
private enum KeepVaultSupervisor {
    static func main() {
        let targetProcess = getppid()
        guard targetProcess > 1 else {
            _exit(78)
        }

        do {
            let launcherCode = try dynamicCode(for: targetProcess)
            try validateDynamicCode(
                launcherCode,
                requirementText: try requirementText(identifier: bundleIdentifier))
            let launcherRequirement = try requirementText(identifier: bundleIdentifier)
            let coreRequirement = try requirementText(
                identifier: coreIdentifier,
                cdHashes: KeepVaultCoreApplePins.cdHashes)
            try writeReadyByte()

            var unrecognizedCodeAttempts = 0
            for _ in 0..<maximumTransitionAttempts {
                guard getppid() == targetProcess else {
                    terminateTarget(targetProcess, reason: "The supervised launcher process disappeared.")
                }
                do {
                    let candidate = try dynamicCode(for: targetProcess)
                    if dynamicCodeSatisfies(candidate, requirementText: coreRequirement) {
                        guard kill(targetProcess, SIGCONT) == 0 else {
                            terminateTarget(targetProcess, reason: "The verified Core could not be resumed (errno \(errno)).")
                        }
                        _exit(0)
                    }
                    if dynamicCodeSatisfies(candidate, requirementText: launcherRequirement) {
                        unrecognizedCodeAttempts = 0
                        usleep(transitionDelayMicroseconds)
                        continue
                    }
                    unrecognizedCodeAttempts += 1
                    if unrecognizedCodeAttempts >= 10 {
                        terminateTarget(targetProcess, reason: "The suspended replacement did not match the pinned Core CDHash.")
                    }
                } catch {
                    // During SETEXEC, the old dynamic code can disappear briefly
                    // before the suspended replacement is visible to Security.framework.
                    unrecognizedCodeAttempts += 1
                    if unrecognizedCodeAttempts >= 100 {
                        terminateTarget(targetProcess, reason: "Security.framework could not inspect the suspended replacement.")
                    }
                }
                usleep(transitionDelayMicroseconds)
            }
            terminateTarget(targetProcess, reason: "Timed out before a valid suspended Core appeared.")
        } catch {
            terminateTarget(targetProcess, reason: (error as? SupervisorFailure)?.message ?? error.localizedDescription)
        }
    }
}
