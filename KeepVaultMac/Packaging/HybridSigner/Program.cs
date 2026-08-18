using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using KalynaArchiver.Signing;

return await RunAsync(args).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        if (args.Length == 0)
        {
            return Usage("A command is required.");
        }

        (Dictionary<string, string> options, List<string> targets) = ParseOptions(args[1..]);
        if (string.Equals(args[0], "wrap-mldsa-key", StringComparison.OrdinalIgnoreCase))
        {
            // No --target: these commands consume a secret, not artifacts.
            return WrapMldsaKey(options);
        }

        if (string.Equals(args[0], "wrap-pfx-password", StringComparison.OrdinalIgnoreCase))
        {
            return WrapPfxPassword(options);
        }

        if (targets.Count == 0)
        {
            return Usage("At least one --target is required.");
        }

        return args[0].ToUpperInvariant() switch
        {
            "SIGN" => await SignAsync(options, targets).ConfigureAwait(false),
            "VERIFY" => Verify(options, targets),
            _ => Usage($"Unknown command: {args[0]}"),
        };
    }
    catch (Exception ex) when (ex is ArgumentException or IOException or InvalidDataException or CryptographicException
        or InvalidOperationException or PlatformNotSupportedException or UnauthorizedAccessException)
    {
        await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
        return 2;
    }
}

static async Task<int> SignAsync(Dictionary<string, string> options, IReadOnlyList<string> targets)
{
    string pfxPath = Require(options, "pfx");
    string publicKeyPath = Require(options, "mldsa-public-key");
    string referencePath = Require(options, "reference-library");
    string policyPath = Require(options, "policy");
    string launcherPinsPath = Require(options, "launcher-pins");

    RequirePrivateFileProtection(pfxPath, "RSA PFX");

    // One confirmation releases the whole hybrid certificate. Both halves are
    // useless alone -- a signature counts only when RSA-PSS and ML-DSA-87 both
    // verify -- so gating them separately would mean two prompts for one
    // indivisible decision.
    byte[]? wrappingKey = ReadWrappingKeyWhenNeeded(options);
    byte[] privateKey;
    string password;
    try
    {
        privateKey = ReadMldsaPrivateKey(options, wrappingKey);
        password = ReadPfxPassword(options, wrappingKey);
    }
    finally
    {
        if (wrappingKey is not null)
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }
    byte[] publicKey = ReadExactFile(publicKeyPath, Mldsa87.PublicKeyBytes, "ML-DSA-87 public key");
    string? macTemporaryKeychainDirectory = OperatingSystem.IsMacOS()
        ? PrepareMacTemporaryKeychainDirectory()
        : null;
    X509Certificate2? certificate = null;
    try
    {
        X509KeyStorageFlags storageFlags = OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.DefaultKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        certificate = X509CertificateLoader.LoadPkcs12FromFile(
            pfxPath,
            password,
            storageFlags);
        HybridSignaturePolicy policy = LoadPolicy(policyPath, publicKey);
        if (!policy.MatchesRsaCertificate(certificate, out string pinError))
        {
            throw new CryptographicException(pinError);
        }

        byte[] derivedPublicKey = Mldsa87.DerivePublicKey(privateKey);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(derivedPublicKey, publicKey))
            {
                throw new CryptographicException("The ML-DSA-87 private key does not match the pinned public key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedPublicKey);
        }

        using var reference = new Mldsa87Reference(referencePath);
        CrossCheckMldsa(reference, privateKey, publicKey);

        foreach (string targetValue in targets)
        {
            string target = RequireRegularFile(targetValue, "hybrid-signing target");
            (byte[] sha256, byte[] sha3, byte[] skein) = Fingerprint(target);
            try
            {
                WriteTextAtomically(target + ".sha3", Convert.ToHexString(sha3) + "\n");
                WriteTextAtomically(target + ".skein", Convert.ToHexString(skein) + "\n");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sha256);
                CryptographicOperations.ZeroMemory(sha3);
                CryptographicOperations.ZeroMemory(skein);
            }

            foreach (string signedPath in new[] { target, target + ".sha3", target + ".skein" })
            {
                using HybridSignatureCreationResult creation = await HybridSignatureService.CreateAsync(
                    signedPath,
                    signedPath + HybridSignatureService.SidecarExtension,
                    certificate,
                    privateKey,
                    publicKey).ConfigureAwait(false);
                if (!reference.Verify(creation.Payload, creation.MldsaSignature, publicKey))
                {
                    throw new CryptographicException($"The pinned ML-DSA reference implementation rejected {Path.GetFileName(signedPath)}.");
                }
                HybridSignatureVerificationResult verification = HybridSignatureService.VerifyFile(
                    signedPath,
                    signedPath + HybridSignatureService.SidecarExtension,
                    policy);
                if (!verification.IsTrusted)
                {
                    throw new CryptographicException($"Hybrid signature verification failed for {Path.GetFileName(signedPath)}: {verification.Message}");
                }
            }

            // Signing always writes the sidecars adjacent to the payload; the
            // relocation into Contents/Resources happens afterwards in the
            // packaging step.
            VerifyManifests(target, target);
            Console.WriteLine($"hybrid_signed={target}");
        }

        WriteLauncherPins(launcherPinsPath, certificate.RawData, publicKey);
        Console.WriteLine($"launcher_pins={Path.GetFullPath(launcherPinsPath)}");
        return 0;
    }
    finally
    {
        try
        {
            certificate?.Dispose();
            if (macTemporaryKeychainDirectory is not null)
            {
                // Apple private keys require a temporary on-disk keychain. Dispose
                // every Security.framework handle before checking that .NET removed it.
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
        }
        if (macTemporaryKeychainDirectory is not null)
        {
            RequireDirectoryEmpty(macTemporaryKeychainDirectory, "temporary macOS keychain directory");
        }
    }
}

static string PrepareMacTemporaryKeychainDirectory()
{
    string configured = Environment.GetEnvironmentVariable("KEEPVAULT_KEYCHAIN_TEMP_ROOT")
        ?? throw new CryptographicException(
            "KEEPVAULT_KEYCHAIN_TEMP_ROOT is required for isolated macOS PFX loading. Use the release build script.");
    string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configured));
    var directory = new DirectoryInfo(fullPath);
    if (!directory.Exists
        || directory.LinkTarget is not null
        || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
    {
        throw new CryptographicException("The temporary macOS keychain directory is missing or is a symbolic link.");
    }

    UnixFileMode mode = File.GetUnixFileMode(fullPath);
    UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    if ((mode & forbidden) != 0)
    {
        throw new CryptographicException("The temporary macOS keychain directory must be private to the release user.");
    }

    string runtimeTemporaryPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
    if (!string.Equals(runtimeTemporaryPath, fullPath, StringComparison.Ordinal))
    {
        throw new CryptographicException("TMPDIR does not resolve to KEEPVAULT_KEYCHAIN_TEMP_ROOT.");
    }

    RequireDirectoryEmpty(fullPath, "temporary macOS keychain directory");
    return fullPath;
}

static void RequireDirectoryEmpty(string path, string description)
{
    string? unexpected = Directory.EnumerateFileSystemEntries(path).FirstOrDefault();
    if (unexpected is not null)
    {
        throw new CryptographicException(
            $"The {description} contains a residual object: {Path.GetFileName(unexpected)}");
    }
}

static int Verify(Dictionary<string, string> options, IReadOnlyList<string> targets)
{
    string publicKeyPath = Require(options, "mldsa-public-key");
    byte[] publicKey = ReadExactFile(publicKeyPath, Mldsa87.PublicKeyBytes, "ML-DSA-87 public key");
    try
    {
        HybridSignaturePolicy policy = LoadPolicy(Require(options, "policy"), publicKey);
        options.TryGetValue("payload-root", out string? payloadRoot);
        options.TryGetValue("signature-root", out string? signatureRoot);
        if (payloadRoot is null != (signatureRoot is null))
        {
            throw new ArgumentException("--payload-root and --signature-root must be supplied together.");
        }

        foreach (string targetValue in targets)
        {
            string target = RequireRegularFile(targetValue, "hybrid-verification target");
            string sidecarBase = ResolveSidecarBase(target, payloadRoot, signatureRoot);
            VerifyManifests(target, sidecarBase);
            (string Payload, string Sidecar)[] signedPairs =
            [
                (target, sidecarBase + HybridSignatureService.SidecarExtension),
                (sidecarBase + ".sha3", sidecarBase + ".sha3" + HybridSignatureService.SidecarExtension),
                (sidecarBase + ".skein", sidecarBase + ".skein" + HybridSignatureService.SidecarExtension),
            ];
            foreach ((string signedPath, string sidecarPath) in signedPairs)
            {
                HybridSignatureVerificationResult result = HybridSignatureService.VerifyFile(
                    signedPath,
                    sidecarPath,
                    policy);
                if (!result.IsTrusted)
                {
                    throw new CryptographicException($"Hybrid signature verification failed for {Path.GetFileName(signedPath)}: {result.Message}");
                }
            }
            Console.WriteLine($"hybrid_verified={target}");
        }
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(publicKey);
    }
}

static void CrossCheckMldsa(Mldsa87Reference reference, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
{
    byte[] message = SHA512.HashData("Keep Vault macOS hybrid signing reference cross-check v1"u8);
    byte[]? managedSignature = null;
    byte[]? referenceSignature = null;
    try
    {
        managedSignature = Mldsa87.Sign(message, privateKey);
        referenceSignature = reference.Sign(message, privateKey);
        if (!reference.Verify(message, managedSignature, publicKey)
            || !Mldsa87.Verify(message, referenceSignature, publicKey))
        {
            throw new CryptographicException("Managed and pinned reference ML-DSA-87 implementations do not agree.");
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(message);
        if (managedSignature is not null) CryptographicOperations.ZeroMemory(managedSignature);
        if (referenceSignature is not null) CryptographicOperations.ZeroMemory(referenceSignature);
    }
}

static (byte[] Sha256, byte[] Sha3, byte[] Skein) Fingerprint(string path)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
    return HybridSignatureService.Fingerprint(stream);
}

/// <summary>
/// Maps a payload file to the base path of its detached sidecars. Inside a
/// signed app bundle the sidecars are relocated out of Contents/MacOS, which
/// Apple reserves for Mach-O executables, into Contents/Resources.
/// </summary>
static string ResolveSidecarBase(string target, string? payloadRoot, string? signatureRoot)
{
    if (payloadRoot is null || signatureRoot is null)
    {
        return target;
    }

    string fullPayloadRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(payloadRoot));
    string fullTarget = Path.GetFullPath(target);
    if (!fullTarget.StartsWith(fullPayloadRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
    {
        throw new CryptographicException(
            $"Hybrid-verification target lies outside the payload root: {target}");
    }

    string relative = fullTarget[(fullPayloadRoot.Length + 1)..];
    return Path.Combine(Path.GetFullPath(signatureRoot), relative);
}

static void VerifyManifests(string target, string sidecarBase)
{
    (byte[] sha256, byte[] sha3, byte[] skein) = Fingerprint(target);
    try
    {
        string expectedSha3 = ReadHexManifest(sidecarBase + ".sha3", 128);
        string expectedSkein = ReadHexManifest(sidecarBase + ".skein", 256);
        byte[] expectedSha3Bytes = Convert.FromHexString(expectedSha3);
        byte[] expectedSkeinBytes = Convert.FromHexString(expectedSkein);
        try
        {
            if (!(CryptographicOperations.FixedTimeEquals(sha3, expectedSha3Bytes)
                & CryptographicOperations.FixedTimeEquals(skein, expectedSkeinBytes)))
            {
                throw new CryptographicException($"Dual manifest mismatch: {Path.GetFileName(target)}");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSha3Bytes);
            CryptographicOperations.ZeroMemory(expectedSkeinBytes);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sha256);
        CryptographicOperations.ZeroMemory(sha3);
        CryptographicOperations.ZeroMemory(skein);
    }
}

static string ReadHexManifest(string path, int expectedCharacters)
{
    string text = File.ReadAllText(RequireRegularFile(path, "integrity manifest"), Encoding.ASCII);
    string normalized = new(text.Where(character => !char.IsWhiteSpace(character)).ToArray());
    if (normalized.Length != expectedCharacters || normalized.Any(character => !Uri.IsHexDigit(character)))
    {
        throw new InvalidDataException($"Invalid integrity manifest: {Path.GetFileName(path)}");
    }
    return normalized;
}

static HybridSignaturePolicy LoadPolicy(string path, byte[] publicKey)
{
    XDocument document = XDocument.Load(RequireRegularFile(path, "compiled signing policy"), LoadOptions.None);
    string Property(string name) => document.Descendants(name).Select(element => element.Value.Trim()).FirstOrDefault()
        ?? throw new InvalidDataException($"Signing policy property is missing: {name}");
    return new HybridSignaturePolicy(
        Property("KalynaExpectedSignerSha256"),
        Property("KalynaExpectedSignerSha3_512"),
        Property("KalynaExpectedSignerSkein1024"),
        Property("KalynaExpectedMldsa87Sha256"),
        Property("KalynaExpectedMldsa87Sha3_512"),
        Property("KalynaExpectedMldsa87Skein1024"),
        publicKey);
}

/// <summary>
/// Wraps a plaintext ML-DSA-87 private key into the encrypted envelope that
/// <c>sign</c> reads, and proves the round trip before writing anything.
/// </summary>
/// <remarks>
/// Encrypting lives in the same file as decrypting on purpose. A wrapping tool
/// that reimplements the format is a tool that can drift from it, and the way
/// that failure shows up is an envelope nobody can open -- with the plaintext
/// already deleted.
///
/// The plaintext key is never touched. Removing it stays a separate, deliberate
/// step for whoever knows whether a backup exists.
/// </remarks>
static int WrapMldsaKey(Dictionary<string, string> options)
{
    string privateKeyPath = Require(options, "mldsa-private-key");
    string envelopePath = Require(options, "mldsa-private-key-encrypted");
    RequirePrivateFileProtection(privateKeyPath, "ML-DSA-87 private key");
    RefuseExistingEnvelope(envelopePath);

    byte[] privateKey = ReadExactFile(privateKeyPath, Mldsa87.PrivateKeyBytes, "ML-DSA-87 private key");
    byte[] wrappingKey = ReadWrappingKeyForWrapping(options);
    try
    {
        WriteEnvelope(envelopePath, privateKey, wrappingKey, "ML-DSA-87 private key");
        Console.WriteLine($"envelope={envelopePath}");
        Console.WriteLine("roundtrip_verified=yes");
        Console.WriteLine($"plaintext_key_left_in_place={privateKeyPath}");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(privateKey);
        CryptographicOperations.ZeroMemory(wrappingKey);
    }
}

/// <summary>
/// Moves the RSA PFX password out of its own unprotected Keychain item and into
/// an envelope under the same wrapping key as the ML-DSA half.
/// </summary>
/// <remarks>
/// A hybrid signature is one decision: it counts only when RSA-PSS and ML-DSA-87
/// both verify, so releasing one half without the other buys nothing. Putting
/// both behind the same secret means one confirmation covers the certificate as
/// a whole rather than two covering halves of it.
///
/// The password is read here, inside this process, straight from the existing
/// Keychain item and written encrypted. It is never passed on a command line,
/// where any process could read it out of the process list, and never printed.
/// </remarks>
static int WrapPfxPassword(Dictionary<string, string> options)
{
    string envelopePath = Require(options, "pfx-password-encrypted");
    string sourceService = Require(options, "pfx-password-keychain-service");
    string sourceAccount = options.GetValueOrDefault("pfx-keychain-account") ?? Environment.UserName;
    RefuseExistingEnvelope(envelopePath);

    string password = ReadKeychainPassword(sourceService, sourceAccount);
    byte[] encoded = Encoding.UTF8.GetBytes(password);
    byte[] wrappingKey = ReadWrappingKeyForWrapping(options);
    try
    {
        if (encoded.Length == 0)
        {
            throw new CryptographicException("The PFX password in the Keychain is empty.");
        }

        WriteEnvelope(envelopePath, encoded, wrappingKey, "RSA PFX password");
        Console.WriteLine($"envelope={envelopePath}");
        Console.WriteLine("roundtrip_verified=yes");
        Console.WriteLine($"old_keychain_item_left_in_place={sourceService}");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(encoded);
        CryptographicOperations.ZeroMemory(wrappingKey);
    }
}

static void RefuseExistingEnvelope(string path)
{
    if (File.Exists(path))
    {
        throw new IOException($"An envelope already exists and will not be overwritten: {path}");
    }
}

static byte[] ReadWrappingKeyForWrapping(Dictionary<string, string> options)
{
    return ReadKeychainSecret(
        Require(options, "mldsa-key-keychain-service"),
        options.GetValueOrDefault("mldsa-key-keychain-account") ?? Environment.UserName,
        "hybrid signing wrapping key");
}

/// <summary>
/// The ML-DSA-87 private key, either from a plain file or from an encrypted
/// envelope whose wrapping key lives in the macOS Keychain.
/// </summary>
/// <remarks>
/// The RSA half has always been a PKCS#12 container whose password sits in the
/// Keychain, so copying the file alone gains nothing. The ML-DSA half was a raw
/// 4896-byte key on disk: whoever copied the file had the key. This closes that
/// asymmetry.
///
/// Encryption at rest stops the file from being useful once it leaves the
/// machine -- in a backup, on a cloned disk, inside a tar of the home directory.
/// It does not stop malware running as the same user, which can simply ask the
/// Keychain the way this code does. What raises that bar is the Keychain item's
/// own access control: created with no trusted application, it prompts on every
/// read, so a use nobody triggered is visible rather than silent.
/// </remarks>
static byte[]? ReadWrappingKeyWhenNeeded(Dictionary<string, string> options)
{
    bool needed = options.ContainsKey("mldsa-private-key-encrypted")
        || options.ContainsKey("pfx-password-encrypted");
    if (!needed)
    {
        return null;
    }

    string service = options.GetValueOrDefault("mldsa-key-keychain-service")
        ?? throw new CryptographicException(
            "An encrypted key or password requires --mldsa-key-keychain-service.");
    return ReadKeychainSecret(
        service,
        options.GetValueOrDefault("mldsa-key-keychain-account") ?? Environment.UserName,
        "hybrid signing wrapping key");
}

static byte[] ReadMldsaPrivateKey(Dictionary<string, string> options, byte[]? wrappingKey)
{
    if (options.TryGetValue("mldsa-private-key-encrypted", out string? envelopePath))
    {
        RequirePrivateFileProtection(envelopePath, "ML-DSA-87 key envelope");
        byte[] key = DecryptEnvelope(
            envelopePath,
            wrappingKey ?? throw new CryptographicException("The wrapping key was not read."),
            "ML-DSA-87 private key");
        if (key.Length != Mldsa87.PrivateKeyBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException(
                $"The envelope holds {key.Length} bytes, not an ML-DSA-87 private key.");
        }

        return key;
    }

    string privateKeyPath = Require(options, "mldsa-private-key");
    RequirePrivateFileProtection(privateKeyPath, "ML-DSA-87 private key");
    return ReadExactFile(privateKeyPath, Mldsa87.PrivateKeyBytes, "ML-DSA-87 private key");
}

/// <summary>
/// Envelope layout: magic, 12-byte nonce, ciphertext, 16-byte AES-GCM tag.
/// </summary>
/// <remarks>
/// The Keychain secret is 32 random bytes and is used directly as the AES-256
/// key. No password-based derivation is involved because nothing here is a
/// human-chosen password -- a KDF would add cost without adding entropy.
/// </remarks>
static byte[] EnvelopeMagic() => "KVSECRT1"u8.ToArray();

static byte[] DecryptEnvelope(string path, byte[] wrappingKey, string description)
{
    const int nonceBytes = 12;
    const int tagBytes = 16;
    byte[] magic = EnvelopeMagic();
    byte[] envelope = File.ReadAllBytes(path);
    try
    {
        int minimum = magic.Length + nonceBytes + tagBytes;
        if (envelope.Length <= minimum)
        {
            throw new CryptographicException($"The {description} envelope is too short to hold anything.");
        }

        if (!CryptographicOperations.FixedTimeEquals(envelope.AsSpan(0, magic.Length), magic))
        {
            throw new CryptographicException($"The {description} envelope has an unknown format.");
        }

        if (wrappingKey.Length != 32)
        {
            throw new CryptographicException(
                $"The wrapping key must be 32 bytes, not {wrappingKey.Length}.");
        }

        int payloadLength = envelope.Length - minimum;
        byte[] payload = new byte[payloadLength];
        try
        {
            using var aes = new AesGcm(wrappingKey, tagBytes);
            aes.Decrypt(
                envelope.AsSpan(magic.Length, nonceBytes),
                envelope.AsSpan(magic.Length + nonceBytes, payloadLength),
                envelope.AsSpan(envelope.Length - tagBytes, tagBytes),
                payload,
                magic);
            return payload;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(payload);
            throw;
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(envelope);
    }
}

static void WriteEnvelope(string path, byte[] payload, byte[] wrappingKey, string description)
{
    const int nonceBytes = 12;
    const int tagBytes = 16;
    if (wrappingKey.Length != 32)
    {
        throw new CryptographicException($"The wrapping key must be 32 bytes, not {wrappingKey.Length}.");
    }

    byte[] magic = EnvelopeMagic();
    byte[] envelope = new byte[magic.Length + nonceBytes + payload.Length + tagBytes];
    try
    {
        magic.CopyTo(envelope, 0);
        RandomNumberGenerator.Fill(envelope.AsSpan(magic.Length, nonceBytes));
        using (var aes = new AesGcm(wrappingKey, tagBytes))
        {
            aes.Encrypt(
                envelope.AsSpan(magic.Length, nonceBytes),
                payload,
                envelope.AsSpan(magic.Length + nonceBytes, payload.Length),
                envelope.AsSpan(envelope.Length - tagBytes, tagBytes),
                magic);
        }

        string temporary = path + ".partial";
        File.WriteAllBytes(temporary, envelope);
        File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        // Read it back through the very path sign uses. An envelope only the
        // writer can open is worth nothing, and the way that shows up is after
        // the original has been deleted.
        byte[] recovered = DecryptEnvelope(temporary, wrappingKey, description);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(recovered, payload))
            {
                File.Delete(temporary);
                throw new CryptographicException($"The wrapped {description} did not decrypt back to the original.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recovered);
        }

        File.Move(temporary, path);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(envelope);
    }
}

/// <summary>
/// Reads a Keychain password as text, the form the RSA PFX password is stored in.
/// </summary>
static string ReadKeychainPassword(string service, string account)
{
    if (!OperatingSystem.IsMacOS())
    {
        throw new CryptographicException("Keychain passwords can only be read on macOS.");
    }

    var start = new ProcessStartInfo("/usr/bin/security")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    start.ArgumentList.Add("find-generic-password");
    start.ArgumentList.Add("-s");
    start.ArgumentList.Add(service);
    start.ArgumentList.Add("-a");
    start.ArgumentList.Add(account);
    start.ArgumentList.Add("-w");
    using Process process = Process.Start(start)
        ?? throw new InvalidOperationException("Unable to start macOS Keychain lookup.");
    string password = process.StandardOutput.ReadToEnd().TrimEnd('\r', '\n');
    string error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    if (process.ExitCode != 0 || password.Length == 0)
    {
        throw new CryptographicException($"macOS Keychain did not provide the password: {error.Trim()}");
    }

    return password;
}

/// <summary>
/// Reads a base64 secret out of the login Keychain.
/// </summary>
static byte[] ReadKeychainSecret(string service, string account, string description)
{
    if (!OperatingSystem.IsMacOS())
    {
        throw new CryptographicException($"The {description} can only be read from the macOS Keychain.");
    }

    var start = new ProcessStartInfo("/usr/bin/security")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    start.ArgumentList.Add("find-generic-password");
    start.ArgumentList.Add("-s");
    start.ArgumentList.Add(service);
    start.ArgumentList.Add("-a");
    start.ArgumentList.Add(account);
    start.ArgumentList.Add("-w");
    using Process process = Process.Start(start)
        ?? throw new InvalidOperationException("Unable to start macOS Keychain lookup.");
    string encoded = process.StandardOutput.ReadToEnd().TrimEnd('\r', '\n');
    string error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    if (process.ExitCode != 0 || encoded.Length == 0)
    {
        throw new CryptographicException(
            $"macOS Keychain did not provide the {description}: {error.Trim()}");
    }

    try
    {
        return Convert.FromBase64String(encoded);
    }
    catch (FormatException)
    {
        throw new CryptographicException($"The {description} in the Keychain is not valid base64.");
    }
}

static string ReadPfxPassword(Dictionary<string, string> options, byte[]? wrappingKey)
{
    if (options.TryGetValue("pfx-password-encrypted", out string? envelopePath))
    {
        RequirePrivateFileProtection(envelopePath, "RSA PFX password envelope");
        byte[] encoded = DecryptEnvelope(
            envelopePath,
            wrappingKey ?? throw new CryptographicException("The wrapping key was not read."),
            "RSA PFX password");
        try
        {
            return Encoding.UTF8.GetString(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    if (options.TryGetValue("pfx-password-keychain-service", out string? service))
    {
        return ReadKeychainPassword(
            service,
            options.GetValueOrDefault("pfx-keychain-account") ?? Environment.UserName);
    }

    string variable = options.GetValueOrDefault("pfx-password-env") ?? "KEEPVAULT_HYBRID_PFX_PASSWORD";
    return Environment.GetEnvironmentVariable(variable)
        ?? throw new CryptographicException($"PFX password is unavailable. Prefer --pfx-password-keychain-service or set {variable}.");
}

static void RequirePrivateFileProtection(string path, string description)
{
    string fullPath = RequireRegularFile(path, description);
    if (!OperatingSystem.IsMacOS()) return;
    UnixFileMode mode = File.GetUnixFileMode(fullPath);
    UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    if ((mode & forbidden) != 0)
    {
        throw new CryptographicException($"{description} must not be accessible to group or other users: {fullPath}");
    }
}

static byte[] ReadExactFile(string path, int expectedBytes, string description)
{
    string fullPath = RequireRegularFile(path, description);
    using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
    if (stream.Length != expectedBytes)
    {
        throw new InvalidDataException($"{description} must contain exactly {expectedBytes} bytes.");
    }
    byte[] result = new byte[expectedBytes];
    stream.ReadExactly(result);
    return result;
}

static string RequireRegularFile(string path, string description)
{
    string fullPath = Path.GetFullPath(path);
    var info = new FileInfo(fullPath);
    if (!info.Exists || info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
    {
        throw new FileNotFoundException($"{description} is missing, not regular, or a symbolic link.", fullPath);
    }
    return fullPath;
}

static void WriteTextAtomically(string path, string contents)
{
    WriteBytesAtomically(path, Encoding.ASCII.GetBytes(contents));
}

static void WriteLauncherPins(string path, byte[] certificate, byte[] publicKey)
{
    byte[] certificateSha256 = SHA256.HashData(certificate);
    try
    {
        string source = "// Generated by KeepVaultMac.HybridSigner. Do not edit.\n"
            + "enum KeepVaultHybridPins {\n"
            + "    static let rsaCertificateSha256: [UInt8] = [\n"
            + FormatSwiftBytes(certificateSha256, 8)
            + "    ]\n"
            + "    static let mldsaPublicKey: [UInt8] = [\n"
            + FormatSwiftBytes(publicKey, 8)
            + "    ]\n"
            + "}\n";
        WriteBytesAtomically(path, Encoding.UTF8.GetBytes(source));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(certificateSha256);
    }
}

static string FormatSwiftBytes(ReadOnlySpan<byte> bytes, int indentation)
{
    var builder = new StringBuilder();
    string prefix = new(' ', indentation);
    for (int offset = 0; offset < bytes.Length; offset += 16)
    {
        builder.Append(prefix);
        int count = Math.Min(16, bytes.Length - offset);
        for (int index = 0; index < count; index++)
        {
            if (index != 0) builder.Append(' ');
            builder.Append("0x");
            builder.Append(bytes[offset + index].ToString("X2"));
            builder.Append(',');
        }
        builder.AppendLine();
    }
    return builder.ToString();
}

static void WriteBytesAtomically(string path, byte[] contents)
{
    string fullPath = Path.GetFullPath(path);
    string directory = Path.GetDirectoryName(fullPath)
        ?? throw new InvalidOperationException("Output path has no parent directory.");
    Directory.CreateDirectory(directory);
    string temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
    try
    {
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(contents);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, fullPath, overwrite: true);
    }
    finally
    {
        File.Delete(temporary);
        CryptographicOperations.ZeroMemory(contents);
    }
}

static (Dictionary<string, string> Options, List<string> Targets) ParseOptions(string[] args)
{
    var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    var targets = new List<string>();
    for (int index = 0; index < args.Length; index += 2)
    {
        if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Invalid option near '{args[index]}'.");
        }
        string name = args[index][2..];
        if (string.Equals(name, "target", StringComparison.OrdinalIgnoreCase))
        {
            targets.Add(args[index + 1]);
        }
        else if (!options.TryAdd(name, args[index + 1]))
        {
            throw new ArgumentException($"Duplicate option: --{name}");
        }
    }
    return (options, targets);
}

static string Require(Dictionary<string, string> options, string name) =>
    options.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new ArgumentException($"Missing required option --{name}.");

static int Usage(string error)
{
    Console.Error.WriteLine(error);
    Console.Error.WriteLine("Usage: sign|verify --target FILE [...] --mldsa-public-key FILE --policy Directory.Build.props");
    return 64;
}
