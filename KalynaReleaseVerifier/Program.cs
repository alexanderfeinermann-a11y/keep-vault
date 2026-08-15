using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: Keep Vault Release Verifier <file-or-directory>");
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
        VerifyFile(target, policy);
        VerifyExternalHashManifestsWhenPresent(target, policy);
    }
    else
    {
        throw new FileNotFoundException("Verification target does not exist.", target);
    }

    Console.WriteLine("RESULT: TRUSTED - RSA-4096/SHA-512 and ML-DSA-87 verification passed.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"RESULT: BLOCKED - {ex.Message}");
    return 3;
}

static void VerifyDirectory(string directory, HybridSignaturePolicy policy)
{
    string[] requiredTopLevelArtifacts =
    [
        "Keep Vault.exe",
        "Keep Vault Release Verifier.exe",
        "zpaq.exe",
        "argon2.exe",
        "argon2_ref.dll",
        "kalyna_ref.dll",
        "threefish_ref.dll",
        "PORTABLE_README.txt",
    ];
    foreach (string required in requiredTopLevelArtifacts)
    {
        string requiredPath = Path.Combine(directory, required);
        if (!File.Exists(requiredPath))
        {
            throw new InvalidDataException($"Required portable release artifact is missing: {required}");
        }
    }

    var files = new List<string>();
    var pending = new Stack<string>();
    pending.Push(directory);
    while (pending.Count > 0)
    {
        string current = pending.Pop();
        var directoryInfo = new DirectoryInfo(current);
        if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Reparse-point directory is forbidden: {current}");
        }

        foreach (string childDirectory in Directory.EnumerateDirectories(current))
        {
            pending.Push(childDirectory);
        }

        foreach (string file in Directory.EnumerateFiles(current))
        {
            var fileInfo = new FileInfo(file);
            if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"Reparse-point file is forbidden: {file}");
            }

            files.Add(fileInfo.FullName);
        }
    }

    foreach (string signature in files.Where(file => file.EndsWith(HybridSignatureService.SidecarExtension, StringComparison.OrdinalIgnoreCase)))
    {
        string signedFile = signature[..^HybridSignatureService.SidecarExtension.Length];
        if (!File.Exists(signedFile))
        {
            throw new InvalidDataException($"Orphan hybrid signature: {signature}");
        }
    }

    string[] artifacts = files
        .Where(file => !file.EndsWith(HybridSignatureService.SidecarExtension, StringComparison.OrdinalIgnoreCase))
        .OrderBy(file => file, StringComparer.OrdinalIgnoreCase)
        .ToArray();
    if (artifacts.Length == 0)
    {
        throw new InvalidDataException("The release directory contains no artifacts.");
    }

    foreach (string artifact in artifacts)
    {
        VerifyFile(artifact, policy);
    }

    Console.WriteLine($"directory={directory}");
    Console.WriteLine($"verified_artifacts={artifacts.Length}");
}

static void VerifyFile(string path, HybridSignaturePolicy policy)
{
    HybridSignatureVerificationResult hybrid = HybridSignatureService.VerifyFile(
        path,
        path + HybridSignatureService.SidecarExtension,
        policy);
    if (!hybrid.IsTrusted)
    {
        throw new CryptographicException($"{Path.GetFileName(path)}: {hybrid.Message}");
    }

    if (IsPortableExecutable(path))
    {
        ToolIntegrityStatus status = IntegrityService.CheckFile(path, requireManifest: true);
        if (!status.IsTrusted)
        {
            throw new CryptographicException(
                $"{Path.GetFileName(path)}: Authenticode/hash/hybrid policy failed; {status.SignatureMessage}; {status.HybridSignatureMessage}; {status.Message}");
        }
    }

    Console.WriteLine($"verified={path}");
}

static void VerifyExternalHashManifestsWhenPresent(string path, HybridSignaturePolicy policy)
{
    string sha3Path = path + ".sha3";
    string skeinPath = path + ".skein";
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

    VerifyFile(sha3Path, policy);
    VerifyFile(skeinPath, policy);
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    (byte[] sha3, byte[] skein) = IntegrityService.HashStream(stream);
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
        if (expectedSha3 is not null) CryptographicOperations.ZeroMemory(expectedSha3);
        if (expectedSkein is not null) CryptographicOperations.ZeroMemory(expectedSkein);
    }
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
        string text = Encoding.ASCII.GetString(contents);
        string normalized = new(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length != expectedBytes * 2 || normalized.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new InvalidDataException($"Invalid hexadecimal manifest: {path}");
        }

        return Convert.FromHexString(normalized);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(contents);
    }
}

static bool IsPortableExecutable(string path)
{
    string extension = Path.GetExtension(path);
    return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".dll", StringComparison.OrdinalIgnoreCase);
}
