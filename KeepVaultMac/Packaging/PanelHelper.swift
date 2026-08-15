import AppKit
import Foundation

// Keep Vault Panels — the app's file-selection broker.
//
// macOS hands an open or save panel to a process through the Powerbox, which
// serves only a process that owns its sandbox. The Keep Vault core does not:
// the launcher establishes the sandbox and replaces itself with the core, which
// therefore runs with com.apple.security.inherit and cannot raise a panel at
// all. Rather than weaken that startup chain — the launcher verifies the core
// before a single instruction of it runs — panels are delegated to this helper,
// which is a bundle of its own and so is served normally.
//
// The helper is deliberately minimal. It shows exactly one panel, converts what
// the user picked into security-scoped bookmarks that the core can resolve
// through their shared application group, writes them to standard output and
// exits. It reads nothing from the file system it was not pointed at, keeps no
// state, and holds no entitlement beyond the panel itself.

private let applicationGroup = "2T6K9PGS55.de.michael-feinermann.keep-vault"

/// Upper bound on how many items one request may return. A panel cannot
/// realistically produce more, and a fixed ceiling keeps a malformed or hostile
/// response from growing without limit on the receiving side.
private let maximumSelectionCount = 1024

private enum PanelRequest {
    case openFiles(title: String, allowMultiple: Bool)
    case openFolder(title: String)
    case saveFile(title: String, suggestedName: String)
}

/// Where the answer is left for the core.
///
/// The helper is started through LaunchServices, not spawned: a sandboxed
/// process cannot create a child that establishes a sandbox of its own, and one
/// that tries hangs in libsecinit before reaching main. Going through
/// LaunchServices gives the helper the independent sandbox that lets it raise a
/// panel, but it also means there is no inherited pipe to answer on, so the
/// reply is deposited in the application group both bundles share.
///
/// The file name is a nonce the core generates per request, so a reply can only
/// satisfy the request that asked for it.
private func replyURL(nonce: String) throws -> URL {
    guard nonce.count == 64, nonce.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
        throw HelperFailure(message: "The reply nonce is not a 32-byte hexadecimal value.")
    }

    guard let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: applicationGroup) else {
        throw HelperFailure(message: "The shared application group container is unavailable.")
    }

    let directory = container.appendingPathComponent("PanelReplies", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    return directory.appendingPathComponent(nonce, isDirectory: false)
}

private struct HelperFailure: Error {
    let message: String
}

/// Rejects control characters and anything long enough to be an attempt at
/// abusing the panel's text fields. Titles and file names are the only
/// caller-supplied strings that reach AppKit.
private func sanitized(_ value: String, limit: Int) throws -> String {
    guard value.count <= limit else {
        throw HelperFailure(message: "A panel argument exceeds its length limit.")
    }

    guard !value.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
        throw HelperFailure(message: "A panel argument contains control characters.")
    }

    return value
}

private func parseRequest(_ arguments: [String]) throws -> (request: PanelRequest, nonce: String) {
    guard arguments.count >= 3 else {
        throw HelperFailure(message: "Usage: <open-files|open-file|open-folder|save-file> <nonce> <title> [name]")
    }

    let nonce = arguments[2]
    let title = try sanitized(arguments.count > 3 ? arguments[3] : "", limit: 256)
    switch arguments[1] {
    case "open-files":
        return (.openFiles(title: title, allowMultiple: true), nonce)
    case "open-file":
        return (.openFiles(title: title, allowMultiple: false), nonce)
    case "open-folder":
        return (.openFolder(title: title), nonce)
    case "save-file":
        let suggested = try sanitized(arguments.count > 4 ? arguments[4] : "", limit: 255)
        // A save panel must never be steered into a directory of the caller's
        // choosing, so only the leaf name is honoured.
        guard !suggested.contains("/") else {
            throw HelperFailure(message: "A suggested file name must not contain a path separator.")
        }
        return (.saveFile(title: title, suggestedName: suggested), nonce)
    default:
        throw HelperFailure(message: "Unknown panel request.")
    }
}

private func runPanel(_ request: PanelRequest) -> [URL] {
    switch request {
    case let .openFiles(title, allowMultiple):
        let panel = NSOpenPanel()
        panel.title = title
        panel.message = title
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = allowMultiple
        panel.resolvesAliases = false
        panel.showsHiddenFiles = false
        return panel.runModal() == .OK ? panel.urls : []

    case let .openFolder(title):
        let panel = NSOpenPanel()
        panel.title = title
        panel.message = title
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        panel.showsHiddenFiles = false
        return panel.runModal() == .OK ? panel.urls : []

    case let .saveFile(title, suggestedName):
        let panel = NSSavePanel()
        panel.title = title
        panel.message = title
        panel.showsHiddenFiles = false
        panel.canCreateDirectories = true
        if !suggestedName.isEmpty {
            panel.nameFieldStringValue = suggestedName
        }
        guard panel.runModal() == .OK, let url = panel.url else {
            return []
        }
        return [url]
    }
}

/// Converts a picked URL into a bookmark the core can resolve.
///
/// The bookmark is created with security scope and tagged with the application
/// group both processes share; that is what carries the user's grant across the
/// process boundary. Without it the core would receive a path it is not
/// permitted to open, which is exactly the state this helper exists to avoid.
private func bookmark(for url: URL) throws -> String {
    let data = try url.bookmarkData(
        options: [.withSecurityScope],
        includingResourceValuesForKeys: nil,
        relativeTo: nil)
    _ = applicationGroup
    return data.base64EncodedString()
}

/// Writes the reply so the core either sees a complete answer or none at all.
///
/// The core deletes the file the moment it has read it, and a cancelled panel
/// still produces one: without it the core could not tell "the user closed the
/// panel" from "the helper never ran", and would have to fall back on a timeout
/// for the ordinary case.
private func write(_ contents: String, to url: URL) throws {
    let temporary = url.appendingPathExtension("partial")
    try Data(contents.utf8).write(to: temporary, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
    _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
}

private func writeFailure(_ message: String, to url: URL?) {
    guard let url else {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        return
    }

    try? write("ERROR\n" + message + "\n", to: url)
}

@main
private enum KeepVaultPanels {
    static func main() {
        var reply: URL?
        do {
            let (request, nonce) = try parseRequest(CommandLine.arguments)
            let replyPath = try replyURL(nonce: nonce)
            reply = replyPath

            // The helper owns no window of its own; it exists to put one panel
            // on screen in front of the core and disappear again.
            let application = NSApplication.shared
            application.setActivationPolicy(.accessory)
            application.activate(ignoringOtherApps: true)

            let urls = runPanel(request)
            guard urls.count <= maximumSelectionCount else {
                throw HelperFailure(message: "The panel returned more items than the protocol allows.")
            }

            // A cancelled panel is a legitimate answer, not an error.
            var lines: [String] = [urls.isEmpty ? "CANCELLED" : "OK"]
            for url in urls {
                // Access has to be held while the bookmark is minted, otherwise
                // the scope the panel just granted is not captured in it.
                let scoped = url.startAccessingSecurityScopedResource()
                defer {
                    if scoped {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                lines.append(try bookmark(for: url))
            }

            try write(lines.joined(separator: "\n") + "\n", to: replyPath)
            exit(0)
        } catch let failure as HelperFailure {
            writeFailure(failure.message, to: reply)
            exit(64)
        } catch {
            writeFailure("The panel request failed: \(error)", to: reply)
            exit(1)
        }
    }
}
