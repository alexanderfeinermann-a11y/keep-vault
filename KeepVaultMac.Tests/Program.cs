using System.Runtime.Versioning;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

[assembly: SupportedOSPlatform("macos14.0")]

var tests = new List<(string Name, Func<Task> Run)>
{
    ("SHA3-512 FIPS vector", TestSha3Async),
    ("HMAC-SHA3-512 vector", TestHmacSha3Async),
    ("descriptor identity", TestDescriptorIdentityAsync),
    ("symlink rejection", TestSymlinkRejectionAsync),
    ("archive-input symlink rejection", TestArchiveInputSymlinkRejectionAsync),
    ("container-private archive-input snapshot", TestArchiveInputSnapshotLocationAsync),
    ("overlapping archive-input normalization", TestOverlappingArchiveInputsAsync),
    ("descriptor-bound private snapshot", TestDescriptorBoundPrivateSnapshotAsync),
    ("private authenticated-input snapshot", TestPrivateSnapshotAsync),
    ("Apple signature framework binding", TestAppleSignatureBindingAsync),
    ("locked secret buffer lifecycle", TestLockedSecretBufferAsync),
    ("password policy", TestPasswordPolicyAsync),
};

foreach ((string name, Func<Task> run) in tests)
{
    await run().ConfigureAwait(false);
    Console.WriteLine($"PASS {name}");
}

Console.WriteLine($"{tests.Count} macOS smoke tests passed.");

if (args.Contains("--full", StringComparer.Ordinal))
{
    await MacComprehensiveTests.RunAsync().ConfigureAwait(false);
}

// Renders both language variants so the printed layout can be inspected as a
// document rather than only asserted on.
int sheetIndex = Array.IndexOf(args, "--dump-key-sheets");
if (sheetIndex >= 0 && sheetIndex + 1 < args.Length)
{
    string outputDirectory = args[sheetIndex + 1];
    Directory.CreateDirectory(outputDirectory);
    string first = new string('A', 0) + string.Concat(Enumerable.Range(0, 128).Select(i => "0123456789abcdef"[(i * 7) % 16]));
    string second = string.Concat(Enumerable.Range(0, 128).Select(i => "0123456789abcdef"[(i * 11 + 3) % 16]));
    foreach (bool english in new[] { false, true })
    {
        var service = new KeySheetService();
        string target = Path.Combine(outputDirectory, english ? "key-sheets-en.pdf" : "key-sheets-de.pdf");
        service.SaveTestPdf(
            new KeySheetData(
                Path.Combine(outputDirectory, "beispiel-archiv.kzpaq"),
                EncryptionSuite.Threefish1024,
                first,
                second,
                DateTime.Now,
                english,
                Environment.MachineName),
            target);
        Console.WriteLine($"key_sheets={target}");
    }
}

static Task TestSha3Async()
{
    string actual = Convert.ToHexString(Sha3_512Compat.HashData([]));
    const string expected = "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26";
    Require(string.Equals(actual, expected, StringComparison.Ordinal), "SHA3-512 empty-message KAT failed.");
    return Task.CompletedTask;
}

static Task TestHmacSha3Async()
{
    byte[] key = Enumerable.Repeat((byte)0x0B, 20).ToArray();
    byte[] message = "Hi There"u8.ToArray();
    byte[] actual;
    try
    {
        using var hmac = new HmacSha3_512(key);
        hmac.AppendData(message);
        actual = hmac.GetHashAndReset();
    }
    finally
    {
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(message);
    }

    try
    {
        const string expected = "EB3FBD4B2EAAB8F5C504BD3A41465AACEC15770A7CABAC531E482F860B5EC7BA47CCB2C6F2AFCE8F88D22B6DC61380F23A668FD3888BB80537C0A0B86407689E";
        Require(string.Equals(Convert.ToHexString(actual), expected, StringComparison.Ordinal), "HMAC-SHA3-512 KAT failed.");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(actual);
    }

    return Task.CompletedTask;
}

static Task TestDescriptorIdentityAsync()
{
    string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing process path.");
    using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(executable);
    MacFileIdentity handle = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
    MacFileIdentity path = MacSafeFileSystem.GetPathIdentityNoFollow(executable);
    Require(handle.SameObject(path), "Path and descriptor do not identify the same file.");
    Require(handle.LinkCount >= 1 && handle.Size > 0, "Invalid fstat layout or values.");
    MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, executable);
    return Task.CompletedTask;
}

static Task TestSymlinkRejectionAsync()
{
    string root = Directory.CreateTempSubdirectory("keep-vault-link-test-").FullName;
    string target = Path.Combine(root, "target");
    string link = Path.Combine(root, "link");
    try
    {
        File.WriteAllText(target, "sentinel");
        File.CreateSymbolicLink(link, target);
        bool rejected = false;
        try
        {
            using FileStream _ = MacSafeFileSystem.OpenReadNoSymlinks(link);
        }
        catch (IOException)
        {
            rejected = true;
        }

        Require(rejected, "O_NOFOLLOW_ANY accepted a symbolic-link input.");
        Require(File.ReadAllText(target) == "sentinel", "Symlink rejection modified the target.");
    }
    finally
    {
        File.Delete(link);
        File.Delete(target);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static Task TestArchiveInputSymlinkRejectionAsync()
{
    string root = Directory.CreateTempSubdirectory("keep-vault-archive-link-test-").FullName;
    string target = Path.Combine(root, "target.txt");
    string link = Path.Combine(root, "linked-secret.txt");
    try
    {
        File.WriteAllText(target, "sentinel");
        File.CreateSymbolicLink(link, target);
        bool rejected = false;
        try
        {
            ZpaqService.ValidatePortableInputTreeForTests(root);
        }
        catch (IOException)
        {
            rejected = true;
        }

        Require(rejected, "An archive input tree containing a symbolic link was accepted.");
        Require(File.ReadAllText(target) == "sentinel", "Archive-input validation modified the symlink target.");
    }
    finally
    {
        File.Delete(link);
        File.Delete(target);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static Task TestArchiveInputSnapshotLocationAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-archive-source-").FullName);
    string source = Path.Combine(sourceRoot, "input.txt");
    File.WriteAllText(source, "sentinel");
    try
    {
        using IDisposable snapshot = ZpaqService.CaptureInputSnapshotForTests(
            sourceRoot,
            new[] { source },
            out string snapshotRoot,
            out string[] snapshotPaths);
        string sourcePrefix = Path.TrimEndingDirectorySeparator(sourceRoot) + Path.DirectorySeparatorChar;
        Require(
            !snapshotRoot.StartsWith(sourcePrefix, StringComparison.Ordinal),
            "The archive input snapshot was created beside user-selected source data.");
        Require(snapshotPaths.Length == 1, "The archive input snapshot did not preserve the selected item count.");
        Require(File.ReadAllText(snapshotPaths[0]) == "sentinel", "The private archive input snapshot changed its content.");
        Require(
            !Directory.EnumerateFileSystemEntries(sourceRoot, ".keep-vault-input-*").Any(),
            "The archive input snapshot left a sibling directory beside user data.");
    }
    finally
    {
        File.Delete(source);
        Directory.Delete(sourceRoot);
    }

    return Task.CompletedTask;
}

static Task TestOverlappingArchiveInputsAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-overlap-source-").FullName);
    string folder = Path.Combine(sourceRoot, "folder");
    string first = Path.Combine(folder, "first.txt");
    string second = Path.Combine(folder, "second.txt");
    Directory.CreateDirectory(folder);
    File.WriteAllText(first, "first");
    File.WriteAllText(second, "second");
    try
    {
        using IDisposable snapshot = ZpaqService.CaptureInputSnapshotForTests(
            sourceRoot,
            new[] { first, folder },
            out _,
            out string[] snapshotPaths);
        Require(snapshotPaths.Length == 1, "A descendant input was not normalized under its selected parent folder.");
        Require(Directory.Exists(snapshotPaths[0]), "The normalized archive snapshot did not retain the parent folder.");
        Require(File.ReadAllText(Path.Combine(snapshotPaths[0], "first.txt")) == "first", "The first overlapping input is missing.");
        Require(File.ReadAllText(Path.Combine(snapshotPaths[0], "second.txt")) == "second", "A sibling file disappeared from the normalized folder snapshot.");
    }
    finally
    {
        File.Delete(first);
        File.Delete(second);
        Directory.Delete(folder);
        Directory.Delete(sourceRoot);
    }

    return Task.CompletedTask;
}

static Task TestDescriptorBoundPrivateSnapshotAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-descriptor-snapshot-").FullName);
    string source = Path.Combine(root, "source.bin");
    string moved = Path.Combine(root, "original.bin");
    File.WriteAllText(source, "original");
    try
    {
        using FileStream handle = MacSafeFileSystem.OpenReadNoSymlinks(source);
        File.Move(source, moved);
        File.WriteAllText(source, "replacement");
        using MacPrivateFileSnapshot snapshot = MacPrivateFileSnapshot.Capture(handle, "captured.bin");
        using var reader = new StreamReader(snapshot.Stream, leaveOpen: true);
        Require(reader.ReadToEnd() == "original", "The private snapshot followed a replaced path instead of its verified descriptor.");
    }
    finally
    {
        File.Delete(source);
        File.Delete(moved);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static async Task TestPrivateSnapshotAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-snapshot-test-").FullName);
    string source = Path.Combine(root, "source.kzpaq");
    byte[] original = RandomNumberGenerator.GetBytes(256 * 1024);
    byte[] replacement = RandomNumberGenerator.GetBytes(original.Length);
    try
    {
        await File.WriteAllBytesAsync(source, original).ConfigureAwait(false);
        using MacPrivateFileSnapshot snapshot = await MacPrivateFileSnapshot
            .CaptureAsync(source, CancellationToken.None)
            .ConfigureAwait(false);
        await File.WriteAllBytesAsync(source, replacement).ConfigureAwait(false);
        byte[] captured = new byte[original.Length];
        try
        {
            snapshot.Stream.Position = 0;
            await snapshot.Stream.ReadExactlyAsync(captured).ConfigureAwait(false);
            Require(CryptographicOperations.FixedTimeEquals(captured, original), "The private snapshot changed with its source.");
            Require(!CryptographicOperations.FixedTimeEquals(captured, replacement), "The private snapshot aliases the mutable source.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(captured);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(original);
        CryptographicOperations.ZeroMemory(replacement);
        File.Delete(source);
        Directory.Delete(root);
    }
}

static Task TestAppleSignatureBindingAsync()
{
    MacSignatureInfo signature = MacCodeSignature.Check("/usr/bin/true");
    Require(signature.State != SignatureState.Unknown, "Apple Security.framework returned no signature state.");
    Require(!string.IsNullOrWhiteSpace(signature.Message), "Apple signature check returned no diagnostic.");
    return Task.CompletedTask;
}

static Task TestLockedSecretBufferAsync()
{
    long before = SecureMemory.LockedBytesForTests;
    using (LockedSensitiveBuffer buffer = LockedSensitiveBuffer.Create(4096))
    {
        RandomNumberGenerator.Fill(buffer.Bytes);
        Require(SecureMemory.LockedBytesForTests >= before + 4096, "Secret buffer was not accounted as locked.");
    }

    Require(SecureMemory.LockedBytesForTests == before, "Secret-buffer lock accounting leaked after disposal.");
    return Task.CompletedTask;
}

static Task TestPasswordPolicyAsync()
{
    const string password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    PasswordPolicyAnalysis valid = PasswordKeyService.AnalyzeUserPassword(password);
    Require(valid.IsAccepted, string.Join("; ", valid.Violations));
    PasswordPolicyAnalysis invalid = PasswordKeyService.AnalyzeUserPassword("0123456789abcdef01234567");
    Require(!invalid.IsAccepted, "A predictable hexadecimal password passed the policy.");
    return Task.CompletedTask;
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
