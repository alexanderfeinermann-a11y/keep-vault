using System.Buffers.Binary;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

// Standalone checker for a Keep Vault macOS release. It is the macOS
// counterpart of the Windows "Keep Vault Release Verifier" and answers one
// question before anything is launched: was every artifact produced by the
// pinned RSA-4096 and ML-DSA-87 keys, and does it still hash to what was
// signed? It carries the same compiled pins as the app and needs no
// installation, no runtime and no network.

if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: \"Keep Vault Release Verifier\" <file-or-app-bundle-or-directory>");
    return 1;
}

try
{
    string target = Path.GetFullPath(args[0]);
    HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
        ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");

    if (Directory.Exists(target))
    {
        VerifyDirectory(target, policy);
    }
    else if (File.Exists(target))
    {
        VerifyArtifact(target, target, policy);
        VerifyExternalHashManifestsWhenPresent(target, target, policy);
    }
    else
    {
        throw new FileNotFoundException("Verification target does not exist.", target);
    }

    Console.WriteLine("RESULT: TRUSTED - RSA-PSS/SHA-512 and ML-DSA-87 verification passed.");
    return 0;
}
catch (OutOfScopeException ex)
{
    // Neither TRUSTED nor BLOCKED. Saying TRUSTED would vouch for something
    // this tool never checked, and saying BLOCKED would accuse an artifact
    // that is not broken.
    Console.WriteLine($"RESULT: NOT COVERED - {ex.Message}");
    return 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"RESULT: BLOCKED - {ex.Message}");
    return 3;
}

/// <summary>
/// Given the base path of a sidecar, returns the payload it signs.
/// </summary>
/// <remarks>
/// Apple reserves Contents/MacOS for Mach-O executables, so a bundle's
/// manifests and hybrid signatures live under Contents/Resources mirroring the
/// layout below Contents/MacOS; such a sidecar signs either the hash manifest
/// beside it or the executable at the mirrored path. Everywhere else the
/// sidecar sits next to what it signs.
///
/// Only this direction is resolved. The reverse -- deriving a sidecar path from
/// a payload -- is not, because two signatures are named after a bundle rather
/// than after the file they cover; the caller remembers where each sidecar was
/// found instead of computing it back.
/// </remarks>
static string? ResolvePayloadPath(string sidecarBase)
{
    if (File.Exists(sidecarBase))
    {
        return sidecarBase;
    }

    // Two signatures are named after a bundle rather than after a file, because
    // they cannot live inside it: the launcher's, which would change the very
    // bundle seal it signs, and a companion bundle's, which would break the
    // Apple seal over Contents/Resources. Both cover the executable that the
    // bundle's Info.plist names.
    const string launcherSuffix = ".launcher";
    string bundleCandidate = sidecarBase.EndsWith(launcherSuffix, StringComparison.Ordinal)
        ? sidecarBase[..^launcherSuffix.Length]
        : sidecarBase;
    if (Directory.Exists(bundleCandidate)
        && string.Equals(Path.GetExtension(bundleCandidate), ".app", StringComparison.OrdinalIgnoreCase))
    {
        return Path.GetFullPath(ReadBundleMainExecutable(bundleCandidate));
    }

    string full = Path.GetFullPath(sidecarBase);
    for (string? directory = Path.GetDirectoryName(full);
        directory is not null;
        directory = Path.GetDirectoryName(directory))
    {
        if (!string.Equals(Path.GetFileName(directory), "HybridSignatures", StringComparison.Ordinal))
        {
            continue;
        }

        string? resources = Path.GetDirectoryName(directory);
        if (resources is null || !string.Equals(Path.GetFileName(resources), "Resources", StringComparison.Ordinal))
        {
            continue;
        }

        string? contents = Path.GetDirectoryName(resources);
        if (contents is null || !string.Equals(Path.GetFileName(contents), "Contents", StringComparison.Ordinal))
        {
            continue;
        }

        string relative = full[(Path.TrimEndingDirectorySeparator(directory).Length + 1)..];
        string candidate = Path.Combine(contents, "MacOS", relative);
        return File.Exists(candidate) ? candidate : null;
    }

    return null;
}

static void VerifyDirectory(string directory, HybridSignaturePolicy policy)
{
    bool isAppBundle = string.Equals(Path.GetExtension(directory), ".app", StringComparison.OrdinalIgnoreCase);
    bool isKeepVaultBundle = isAppBundle
        && File.Exists(Path.Combine(directory, "Contents", "MacOS", "Keep Vault"));
    // A companion bundle -- the QR scanner -- keeps its signature beside itself
    // rather than inside, because Apple's seal covers Contents/Resources and a
    // file added there afterwards would invalidate the seal it lives under. The
    // sidecar therefore has to be looked for one level up.
    string? companionSidecarBase = null;
    if (isAppBundle && !isKeepVaultBundle)
    {
        string besideBundle = directory.TrimEnd(Path.DirectorySeparatorChar);
        if (File.Exists(besideBundle + HybridSignatureService.SidecarExtension))
        {
            companionSidecarBase = besideBundle;
        }
        else
        {
            throw new OutOfScopeException(
                $"{Path.GetFileName(directory)} is not the Keep Vault bundle and has no "
                + $"{Path.GetFileName(besideBundle)}{HybridSignatureService.SidecarExtension} beside it. "
                + "This tool only checks artifacts signed with Keep Vault's pinned release keys. "
                + "Verify this bundle with Apple's own tooling instead: "
                + $"codesign --verify --strict --deep \"{directory}\"");
        }
    }

    if (isKeepVaultBundle)
    {
        string[] required =
        [
            "Contents/MacOS/Keep Vault",
            "Contents/MacOS/Keep Vault Launcher",
            "Contents/MacOS/Keep Vault Supervisor",
            "Contents/MacOS/Native/zpaq",
            "Contents/MacOS/Native/argon2",
            "Contents/MacOS/Native/libargon2_ref.dylib",
            "Contents/MacOS/Native/libkalyna_ref.dylib",
            "Contents/MacOS/Native/libthreefish_ref.dylib",
            "Contents/Info.plist",
        ];
        foreach (string relative in required)
        {
            if (!File.Exists(Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar))))
            {
                throw new InvalidDataException($"Required app-bundle artifact is missing: {relative}");
            }
        }
    }

    List<string> files = EnumerateWithoutSymlinks(directory);

    // Every signature must belong to a payload that is actually present, so a
    // dropped executable cannot pass unnoticed as a merely absent file.
    // Payload -> the base name its sidecars actually carry. Remembered while
    // scanning rather than re-derived afterwards: two signatures are named after
    // a bundle instead of after the file they cover, and re-deriving the layout
    // from the payload alone looks for them in the wrong place.
    var signedPayloads = new SortedDictionary<string, string>(StringComparer.Ordinal);
    foreach (string signature in files.Where(file => file.EndsWith(HybridSignatureService.SidecarExtension, StringComparison.OrdinalIgnoreCase)))
    {
        string sidecarBase = signature[..^HybridSignatureService.SidecarExtension.Length];
        string payload = ResolvePayloadPath(sidecarBase)
            ?? throw new InvalidDataException($"Orphan hybrid signature: {signature}");
        signedPayloads[payload] = sidecarBase;
    }

    // A companion bundle verified on its own: its signature sits outside the
    // tree that was just walked, so it has to be registered explicitly. This
    // happens before the closure check below, so that check sees the bundle's
    // executable as covered instead of reporting it as unsigned code.
    string? companionPayload = null;
    if (companionSidecarBase is not null)
    {
        companionPayload = Path.GetFullPath(ReadBundleMainExecutable(directory));
        signedPayloads[companionPayload] = companionSidecarBase;
    }

    if (signedPayloads.Count == 0)
    {
        throw new InvalidDataException("The release directory contains no hybrid-signed artifacts.");
    }

    // The other direction: every executable in the tree has to be one of those
    // payloads. Building the worklist from the signatures alone answered
    // TRUSTED for a bundle whose signature had been deleted -- the artifact
    // simply left the list -- and for one with an extra unsigned library
    // dropped in. Both are what an attacker who can write into the bundle would
    // actually do, so the inventory is closed against the code that is present
    // rather than against the signatures that happen to be there.
    var unsigned = new SortedSet<string>(StringComparer.Ordinal);
    foreach (string file in files)
    {
        if (signedPayloads.ContainsKey(file) || !IsMachO(file))
        {
            continue;
        }

        // The launcher carries the bundle seal, so its own hybrid signature
        // cannot live inside the bundle; it is published beside the app and
        // checked by the launcher itself at every start.
        if (isKeepVaultBundle
            && string.Equals(
                Path.GetRelativePath(directory, file).Replace(Path.DirectorySeparatorChar, '/'),
                "Contents/MacOS/Keep Vault Launcher",
                StringComparison.Ordinal))
        {
            continue;
        }

        unsigned.Add(file);
    }

    if (unsigned.Count > 0)
    {
        throw new InvalidDataException(
            "Executable code without a hybrid signature: "
            + string.Join(", ", unsigned.Select(file => Path.GetRelativePath(directory, file))));
    }

    foreach ((string payload, string sidecarBase) in signedPayloads)
    {
        VerifyArtifact(payload, sidecarBase, policy);
    }

    if (companionSidecarBase is not null)
    {
        VerifyExternalHashManifestsWhenPresent(companionPayload!, companionSidecarBase, policy);
    }

    string[] payloads = [.. signedPayloads.Keys];

    Console.WriteLine($"directory={directory}");
    Console.WriteLine($"verified_artifacts={payloads.Length}");
}

/// <summary>
/// Whether a file is Mach-O, thin or fat, in either byte order.
/// </summary>
/// <remarks>
/// Read from the file rather than inferred from its name or its permission
/// bits: a planted library is named whatever its author wants, and a dylib does
/// not need the executable bit to be loaded into a process.
/// </remarks>
static bool IsMachO(string path)
{
    Span<byte> magic = stackalloc byte[4];
    using (FileStream stream = File.OpenRead(path))
    {
        if (stream.ReadAtLeast(magic, magic.Length, throwOnEndOfStream: false) < magic.Length)
        {
            return false;
        }
    }

    uint value = BinaryPrimitives.ReadUInt32BigEndian(magic);
    return value is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE or 0xBEBAFECA;
}

/// <summary>
/// The Mach-O named by CFBundleExecutable, which is the file a companion
/// bundle's detached signature covers.
/// </summary>
static string ReadBundleMainExecutable(string bundle)
{
    string plist = Path.Combine(bundle, "Contents", "Info.plist");
    if (!File.Exists(plist))
    {
        throw new InvalidDataException($"The bundle has no Contents/Info.plist: {bundle}");
    }

    string text = File.ReadAllText(plist);
    const string key = "<key>CFBundleExecutable</key>";
    int keyIndex = text.IndexOf(key, StringComparison.Ordinal);
    int open = keyIndex < 0 ? -1 : text.IndexOf("<string>", keyIndex, StringComparison.Ordinal);
    int close = open < 0 ? -1 : text.IndexOf("</string>", open, StringComparison.Ordinal);
    if (close < 0)
    {
        throw new InvalidDataException($"The bundle declares no CFBundleExecutable: {bundle}");
    }

    string name = text[(open + "<string>".Length)..close].Trim();
    if (name.Length == 0 || name.Contains('/', StringComparison.Ordinal))
    {
        throw new InvalidDataException($"The bundle declares an unusable CFBundleExecutable: {name}");
    }

    string executable = Path.Combine(bundle, "Contents", "MacOS", name);
    if (!File.Exists(executable))
    {
        throw new InvalidDataException($"The declared main executable is missing: Contents/MacOS/{name}");
    }

    return executable;
}

static List<string> EnumerateWithoutSymlinks(string root)
{
    var files = new List<string>();
    var pending = new Stack<string>();
    pending.Push(root);
    while (pending.Count > 0)
    {
        string current = pending.Pop();
        if (new DirectoryInfo(current).LinkTarget is not null)
        {
            throw new InvalidDataException($"Symbolic-link directory is forbidden in a release: {current}");
        }

        foreach (string child in Directory.EnumerateDirectories(current))
        {
            pending.Push(child);
        }

        foreach (string file in Directory.EnumerateFiles(current))
        {
            if (new FileInfo(file).LinkTarget is not null)
            {
                throw new InvalidDataException($"Symbolic-link file is forbidden in a release: {file}");
            }

            files.Add(Path.GetFullPath(file));
        }
    }

    return files;
}

static void VerifyArtifact(string payloadPath, string sidecarBase, HybridSignaturePolicy policy)
{
    HybridSignatureVerificationResult hybrid = HybridSignatureService.VerifyFile(
        payloadPath,
        sidecarBase + HybridSignatureService.SidecarExtension,
        policy);
    if (!hybrid.IsTrusted)
    {
        throw new CryptographicException($"{Path.GetFileName(payloadPath)}: {hybrid.Message}");
    }

    // Assert both halves by name so a future change that quietly accepted the
    // classical signature alone cannot pass as trusted.
    if (!hybrid.RsaPssValid)
    {
        throw new CryptographicException($"{Path.GetFileName(payloadPath)}: RSA-PSS/SHA-512 signature is invalid.");
    }

    if (!hybrid.Mldsa87Valid)
    {
        throw new CryptographicException($"{Path.GetFileName(payloadPath)}: post-quantum ML-DSA-87 signature is invalid.");
    }

    Console.WriteLine($"verified={payloadPath}");
}

/// <summary>
/// Checks the detached SHA3-512 and Skein-1024 manifests that sit beside
/// <paramref name="sidecarBase"/> against <paramref name="payloadPath"/>.
/// </summary>
/// <remarks>
/// The two paths are the same for a plain file. They differ for a companion
/// bundle, whose manifests are named after the bundle but describe the
/// executable inside it -- hashing the bundle path there would try to read a
/// directory.
/// </remarks>
static void VerifyExternalHashManifestsWhenPresent(
    string payloadPath,
    string sidecarBase,
    HybridSignaturePolicy policy)
{
    string sha3Path = sidecarBase + ".sha3";
    string skeinPath = sidecarBase + ".skein";
    bool sha3Exists = File.Exists(sha3Path);
    bool skeinExists = File.Exists(skeinPath);
    if (!(sha3Exists | skeinExists))
    {
        return;
    }

    if (!(sha3Exists & skeinExists))
    {
        throw new InvalidDataException("Only one half of the SHA3-512/Skein-1024 release manifest pair exists.");
    }

    VerifyArtifact(sha3Path, sha3Path, policy);
    VerifyArtifact(skeinPath, skeinPath, policy);

    using var stream = new FileStream(payloadPath, FileMode.Open, FileAccess.Read, FileShare.Read);
    (byte[] _, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(stream);
    byte[]? expectedSha3 = null;
    byte[]? expectedSkein = null;
    try
    {
        expectedSha3 = ParseManifest(sha3Path, 64);
        expectedSkein = ParseManifest(skeinPath, 128);
        if (!(CryptographicOperations.FixedTimeEquals(sha3, expectedSha3)
            & CryptographicOperations.FixedTimeEquals(skein, expectedSkein)))
        {
            throw new CryptographicException("The external SHA3-512/Skein-1024 manifests do not match the release artifact.");
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sha3);
        CryptographicOperations.ZeroMemory(skein);
        if (expectedSha3 is not null)
        {
            CryptographicOperations.ZeroMemory(expectedSha3);
        }

        if (expectedSkein is not null)
        {
            CryptographicOperations.ZeroMemory(expectedSkein);
        }
    }

    Console.WriteLine($"manifests_match={payloadPath}");
}

static byte[] ParseManifest(string path, int expectedBytes)
{
    using var stream = new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        bufferSize: 4096,
        FileOptions.SequentialScan);
    if (stream.Length is <= 0 or > 4096)
    {
        throw new InvalidDataException($"Invalid manifest length: {path}");
    }

    byte[] contents = new byte[checked((int)stream.Length)];
    try
    {
        stream.ReadExactly(contents);
        string text = System.Text.Encoding.ASCII.GetString(contents);
        string normalized = new(text.Where(character => !char.IsWhiteSpace(character)).ToArray());
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException($"Manifest is not a {expectedBytes}-byte hexadecimal digest: {path}");
        }

        return Convert.FromHexString(normalized);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(contents);
    }
}

/// <summary>
/// The target is a real artifact but not one this tool's pins cover.
/// </summary>
internal sealed class OutOfScopeException : Exception
{
    public OutOfScopeException(string message)
        : base(message)
    {
    }
}
