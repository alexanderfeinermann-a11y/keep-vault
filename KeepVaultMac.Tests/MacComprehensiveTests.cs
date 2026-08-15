using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

internal static partial class MacComprehensiveTests
{
    /// <summary>
    /// The Apple Team ID compiled into the app assembly, which every Apple
    /// code-signature check is pinned to. Read from assembly metadata so the
    /// test cannot drift away from the value the build actually signs with.
    /// </summary>
    private static readonly string ExpectedAppleTeamIdentifier =
        typeof(IntegrityService).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, "KeepVaultAppleTeamIdentifier", StringComparison.Ordinal))
            ?.Value
        ?? throw new InvalidOperationException("The pinned Apple Team ID is not compiled into the app assembly.");

    private const string UserPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string WrongPassword = "Q!m8$Ls2#Vx7%Tp4&Jd9*Wr5+Kn6=Zu3?Ce";

    internal static async Task RunAsync()
    {
        (string Name, Func<Task> Run)[] tests =
        [
            ("macOS process hardening", TestProcessHardeningAsync),
            ("signed native trust and tamper rejection", TestNativeTrustAsync),
            ("SHA3, Skein, Kalyna and Threefish reference vectors", TestPrimitiveVectorsAsync),
            ("ML-DSA-87 managed/reference interoperability", TestMldsaInteropAsync),
            ("Argon2id fixed 1 GiB profile and independent equivalence", TestArgon2Async),
            ("ZPAQ levels, streaming, traversal and malformed corpus", TestZpaqAsync),
            ("v7 dual-suite roundtrip and manipulation rejection", TestContainersAsync),
            ("KPAR2-v2 repair, authentication and transplantation rejection", TestRecoveryAsync),
            ("cryptographic erase ordering and hard-link refusal", TestCryptographicEraseAsync),
            // The GUI groups run last: they drive the real window through
            // Avalonia's headless backend and feed the shared entropy pools
            // thousands of pointer samples, which the earlier groups should not
            // inherit.
            .. MacGuiTests.Tests,
        ];

        foreach ((string name, Func<Task> run) in tests)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            await run().ConfigureAwait(false);
            Console.WriteLine($"FULL PASS {name} ({stopwatch.Elapsed.TotalSeconds:F1}s)");
        }

        Console.WriteLine($"{tests.Length} comprehensive macOS functional/cryptographic groups passed.");
    }

    private static Task TestProcessHardeningAsync()
    {
        MacProcessHardeningStatus status = MacProcessHardening.Apply();
        Require(status.AllRequiredApplied, "Required macOS process hardening was not applied.");
        Require(status.CoreDumpsDisabled, "Core dumps remain enabled.");
        Require(status.DebuggerDenied, "Debugger attachment was not denied.");
        Require(status.RestrictiveUmaskApplied, "Private umask was not applied.");
        Require(status.DynamicLoaderEnvironmentCleared, "Dynamic-loader environment was not cleared.");
        return Task.CompletedTask;
    }

    private static readonly string[] NativeLogicalNames =
    [
        "zpaq.exe",
        "argon2.exe",
        "argon2_ref.dll",
        "kalyna_ref.dll",
        "threefish_ref.dll",
    ];

    private static readonly string[] SidecarSuffixes =
        [".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig"];

    /// <summary>
    /// Enumerates the native components exactly as the build shipped them,
    /// inside the signed app bundle, when KEEPVAULT_SIGNED_BUNDLE names one.
    /// </summary>
    /// <remarks>
    /// These are the artifacts whose signatures actually matter, so the trust
    /// group verifies them in place. They cannot be executed here: the shipped
    /// helpers carry com.apple.security.inherit and so require a sandboxed
    /// parent, which a test runner is not. The functional groups therefore run
    /// against the locally staged, re-signed copies produced by
    /// tools/Stage-TestNatives-macOS.sh, which keep every trust gate but drop
    /// the sandbox entitlements.
    /// </remarks>
    private static string? ResolveShippedComponent(string logicalName)
    {
        string? bundle = Environment.GetEnvironmentVariable("KEEPVAULT_SIGNED_BUNDLE");
        return string.IsNullOrEmpty(bundle)
            ? null
            : NativeToolIntegrity.ResolveKnownTool(logicalName, Path.Combine(bundle, "Contents", "MacOS"))
              ?? throw new FileNotFoundException($"Signed native component is unavailable in the bundle: {logicalName}");
    }

    private static string ResolveSignedComponent(string logicalName)
        => NativeToolIntegrity.ResolveKnownTool(logicalName)
            ?? throw new FileNotFoundException($"Signed native component is unavailable: {logicalName}");

    private static Task TestNativeTrustAsync()
    {
        string[] logicalNames = NativeLogicalNames;

        Require(SigningTrustPolicy.IsConfigured, "Compiled hybrid-signature policy is not configured.");
        HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
            ?? throw new InvalidOperationException("Compiled ML-DSA-87 public-key policy is unavailable.");

        foreach (string logicalName in logicalNames)
        {
            string path = ResolveSignedComponent(logicalName);
            Require(File.ResolveLinkTarget(path, returnFinalTarget: false) is null, $"Native component is a symbolic link: {logicalName}");
            string sidecarBase = IntegrityService.ResolveSidecarBasePath(path);
            foreach (string suffix in SidecarSuffixes)
            {
                Require(File.Exists(sidecarBase + suffix), $"Native component sidecar is missing: {logicalName}{suffix}");
            }

            ToolIntegrityStatus status = IntegrityService.CheckFile(path, requireManifest: true);
            Require(status.IsTrusted, $"Native trust failed for {logicalName}: {status.Message} {status.HybridSignatureMessage} {status.SignatureMessage}");
            Require(status.HashMatches, $"Dual manifest failed for {logicalName}.");
            Require(status.HybridSignatureMatches, $"Hybrid RSA-PSS/ML-DSA signature failed for {logicalName}.");
            Require(IntegrityService.IsAcceptedSignatureState(status.SignatureState), $"Apple signature failed for {logicalName}.");

            // Windows pins the Authenticode signer certificate by hash. macOS
            // exposes no equivalent certificate through the Security
            // framework, so ToolIntegrityStatus deliberately reports no signer
            // hashes here. The identical RSA-SPKI and ML-DSA-87 pins are
            // enforced one assertion earlier, inside the hybrid signature
            // check, and the Apple signature is separately bound to the pinned
            // Team ID through a strict designated requirement.
            Require(
                status.SignerSha256 is null && status.SignerSha3_512 is null && status.SignerSkein1024 is null,
                $"macOS reported Authenticode-style signer hashes for {logicalName}; the trust model changed.");
            Require(
                string.Equals(status.Signer, ExpectedAppleTeamIdentifier, StringComparison.Ordinal),
                $"Apple Team ID pin mismatch for {logicalName}: {status.Signer}");

            // Assert both halves of the hybrid signature by name. The
            // post-quantum ML-DSA-87 branch must hold on its own, so a future
            // regression that silently degraded verification to the classical
            // RSA-PSS signature alone would fail here rather than pass.
            HybridSignatureVerificationResult componentSignature = HybridSignatureService.VerifyFile(
                path,
                sidecarBase + HybridSignatureService.SidecarExtension,
                policy);
            Require(componentSignature.RsaPssValid, $"RSA-PSS/SHA-512 signature failed for {logicalName}.");
            Require(componentSignature.Mldsa87Valid, $"Post-quantum ML-DSA-87 signature failed for {logicalName}.");
            Require(componentSignature.IsTrusted, $"Hybrid signature is not trusted for {logicalName}.");
            using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(path);
            Require(File.Exists(lease.Path), $"Authenticated private snapshot missing for {logicalName}.");

            // Repeat the cryptographic checks against the component as the
            // build actually shipped it inside the signed bundle. Those bytes
            // differ from the locally staged copy, which is re-signed without
            // the sandbox entitlements so that it can be executed at all.
            if (ResolveShippedComponent(logicalName) is not { } shippedPath)
            {
                continue;
            }

            string shippedSidecarBase = IntegrityService.ResolveSidecarBasePath(shippedPath);
            ToolIntegrityStatus shipped = IntegrityService.CheckFile(shippedPath, requireManifest: true);
            Require(shipped.IsTrusted, $"Shipped native trust failed for {logicalName}: {shipped.Message} {shipped.HybridSignatureMessage} {shipped.SignatureMessage}");
            Require(shipped.HashMatches, $"Shipped dual manifest failed for {logicalName}.");
            Require(
                string.Equals(shipped.Signer, ExpectedAppleTeamIdentifier, StringComparison.Ordinal),
                $"Shipped Apple Team ID pin mismatch for {logicalName}: {shipped.Signer}");
            HybridSignatureVerificationResult shippedSignature = HybridSignatureService.VerifyFile(
                shippedPath,
                shippedSidecarBase + HybridSignatureService.SidecarExtension,
                policy);
            Require(shippedSignature.RsaPssValid, $"Shipped RSA-PSS/SHA-512 signature failed for {logicalName}.");
            Require(shippedSignature.Mldsa87Valid, $"Shipped post-quantum ML-DSA-87 signature failed for {logicalName}.");
        }

        string signedTarget = ResolveSignedComponent("zpaq.exe");
        string root = CreateTempRoot("keep-vault-hybrid-tamper-");
        try
        {
            string targetCopy = Path.Combine(root, "zpaq");
            string sidecarCopy = targetCopy + ".khsig";
            File.Copy(signedTarget, targetCopy);
            File.Copy(IntegrityService.ResolveSidecarBasePath(signedTarget) + ".khsig", sidecarCopy);
            HybridSignatureVerificationResult intact = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(intact.IsTrusted && intact.RsaPssValid && intact.Mldsa87Valid, "Copied signed bytes failed hybrid verification.");

            FlipByte(targetCopy, new FileInfo(targetCopy).Length / 2);
            HybridSignatureVerificationResult changedTarget = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(!changedTarget.IsTrusted, "One-bit native-component corruption passed hybrid verification.");

            File.Copy(signedTarget, targetCopy, overwrite: true);
            byte[] sidecar = File.ReadAllBytes(sidecarCopy);
            try
            {
                sidecar[^1] ^= 0x01;
                File.WriteAllBytes(sidecarCopy, sidecar);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sidecar);
            }

            HybridSignatureVerificationResult changedSignature = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(!changedSignature.IsTrusted && !changedSignature.Mldsa87Valid, "One-bit ML-DSA signature corruption was accepted.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static Task TestPrimitiveVectorsAsync()
    {
        RequireHex(
            Sha3_512Compat.HashData([]),
            "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
            "SHA3-512 empty-message FIPS 202 vector");
        RequireHex(
            Sha3_512Compat.HashData("abc"u8),
            "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0",
            "SHA3-512 abc FIPS 202 vector");

        byte[] skeinMessage = [0xFF];
        byte[] expectedSkein = Convert.FromHexString(
            "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B" +
            "CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC" +
            "0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832" +
            "E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8");
        byte[] managedSkein = Skein1024Digest.HashData(skeinMessage);
        byte[] nativeSkein = NativeThreefish.HashSkein1024Reference(skeinMessage);
        try
        {
            Require(FixedEqual(expectedSkein, managedSkein), "Managed Skein-1024 failed the official 8-bit KAT.");
            Require(FixedEqual(expectedSkein, nativeSkein), "Native Skein-1024 failed the official 8-bit KAT.");
        }
        finally
        {
            Zero(skeinMessage, expectedSkein, managedSkein, nativeSkein);
        }

        byte[] skeinKey = Convert.FromHexString(
            "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E" +
            "920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1" +
            "935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8" +
            "75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC81463134");
        byte[] expectedMac = Convert.FromHexString(
            "BCF37B3459C88959D6B6B58B2BFE142CEF60C6F4EC56B0702480D7893A2B0595" +
            "AA354E87102A788B61996B9CBC1EADE7DAFBF6581135572C09666D844C90F066" +
            "B800FC4F5FD1737644894EF7D588AFC5C38F5D920BDBD3B738AEA3A3267D161E" +
            "D65284D1F57DA73B68817E17E381CA169115152B869C66B812BB9A84275303F0");
        byte[] nativeMac = NativeThreefish.MacSkein1024Reference(skeinKey, []);
        byte[] independentMac = BouncySkeinMac(skeinKey, []);
        try
        {
            Require(FixedEqual(expectedMac, nativeMac), "Native Skein-1024 MAC failed the official empty-message KAT.");
            Require(FixedEqual(expectedMac, independentMac), "Independent Skein-1024 MAC failed the official KAT.");
        }
        finally
        {
            Zero(skeinKey, expectedMac, nativeMac, independentMac);
        }

        TestKalynaVectorAndParallelism();
        TestThreefishVectorAndParallelism();
        return Task.CompletedTask;
    }

    private static void TestKalynaVectorAndParallelism()
    {
        byte[] key = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        byte[] nonce = Enumerable.Range(0x40, 64).Select(value => (byte)value).ToArray();
        byte[] zero = new byte[64];
        byte[] actual = new byte[64];
        byte[] expected = WordsToLittleEndian(
        [
            0x6a351c811be3264aUL, 0x1a239605cad61da6UL,
            0xa1f347aa5483ba67UL, 0xb856eb20c3ee1d3eUL,
            0x66ab5b1717f4d095UL, 0x6cc815bb34f1d62fUL,
            0xb7fe6e85266a90cbUL, 0xd9d90d947264bcc5UL,
        ]);
        try
        {
            Require(NativeKalyna.IsAvailable(), "Native Kalyna is unavailable after trust validation.");
            NativeKalyna.XCryptCtr512(key, nonce, zero, actual);
            Require(FixedEqual(expected, actual), "Kalyna-512/512 failed the reference CTR block vector.");

            byte[] input = RandomNumberGenerator.GetBytes((10 * 1024 * 1024) + 333);
            byte[] parallel = new byte[input.Length];
            byte[] serial = new byte[input.Length];
            try
            {
                NativeKalyna.XCryptCtr512(key, nonce, input, parallel, input.Length);
                SerialKalyna(key, nonce, input, serial);
                Require(FixedEqual(parallel, serial), "Parallel Kalyna CTR differs from serial counter composition.");
                NativeKalyna.XCryptCtr512(key, nonce, parallel, serial, parallel.Length);
                Require(FixedEqual(input, serial), "Kalyna CTR roundtrip failed.");
            }
            finally
            {
                Zero(input, parallel, serial);
            }
        }
        finally
        {
            Zero(key, nonce, zero, actual, expected);
        }
    }

    private static void TestThreefishVectorAndParallelism()
    {
        byte[] zeroKey = new byte[128];
        byte[] zeroTweak = new byte[16];
        byte[] zeroBlock = new byte[128];
        byte[] actual = new byte[128];
        byte[] expected = WordsToLittleEndian(
        [
            0x04B3053D0A3D5CF0UL, 0x0136E0D1C7DD85F7UL,
            0x067B212F6EA78A5CUL, 0x0DA9C10B4C54E1C6UL,
            0x0F4EC27394CBACF0UL, 0x32437F0568EA4FD5UL,
            0xCFF56D1D7654B49CUL, 0xA2D5FB14369B2E7BUL,
            0x540306B460472E0BUL, 0x71C18254BCEA820DUL,
            0xC36B4068BEAF32C8UL, 0xFA4329597A360095UL,
            0xC4A36C28434A5B9AUL, 0xD54331444B1046CFUL,
            0xDF11834830B2A460UL, 0x1E39E8DFE1F7EE4FUL,
        ]);
        try
        {
            Require(NativeThreefish.IsAvailable(), "Native Threefish is unavailable after trust validation.");
            NativeThreefish.EncryptBlock1024(zeroKey, zeroTweak, zeroBlock, actual);
            Require(FixedEqual(expected, actual), "Threefish-1024 failed the official Skein 1.3 zero vector.");

            for (int index = 0; index < 24; index++)
            {
                byte[] key = RandomNumberGenerator.GetBytes(128);
                byte[] tweak = RandomNumberGenerator.GetBytes(16);
                byte[] input = RandomNumberGenerator.GetBytes(128);
                byte[] native = new byte[128];
                byte[] independent = new byte[128];
                try
                {
                    NativeThreefish.EncryptBlock1024(key, tweak, input, native);
                    var engine = new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024);
                    engine.Init(true, new TweakableBlockCipherParameters(new KeyParameter(key), tweak));
                    Require(engine.ProcessBlock(input, 0, independent, 0) == 128, "Independent Threefish wrote an invalid block length.");
                    Require(FixedEqual(native, independent), $"Native Threefish differs from Bouncy Castle at vector {index}.");
                }
                finally
                {
                    Zero(key, tweak, input, native, independent);
                }
            }

            byte[] parallelKey = RandomNumberGenerator.GetBytes(128);
            byte[] parallelTweak = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(128);
            byte[] data = RandomNumberGenerator.GetBytes((10 * 1024 * 1024) + 333);
            byte[] parallel = new byte[data.Length];
            byte[] serial = new byte[data.Length];
            try
            {
                NativeThreefish.XCryptCtr1024(parallelKey, parallelTweak, nonce, data, parallel, data.Length);
                SerialThreefish(parallelKey, parallelTweak, nonce, data, serial);
                Require(FixedEqual(parallel, serial), "Parallel Threefish CTR differs from serial counter composition.");
                NativeThreefish.XCryptCtr1024(parallelKey, parallelTweak, nonce, parallel, serial, parallel.Length);
                Require(FixedEqual(data, serial), "Threefish CTR roundtrip failed.");
            }
            finally
            {
                Zero(parallelKey, parallelTweak, nonce, data, parallel, serial);
            }
        }
        finally
        {
            Zero(zeroKey, zeroTweak, zeroBlock, actual, expected);
        }
    }

    private static Task TestMldsaInteropAsync()
    {
        string referencePath = Environment.GetEnvironmentVariable("KEEPVAULT_MLDSA_REFERENCE")
            ?? Path.Combine(AppContext.BaseDirectory, "Native", "libmldsa87_ref.dylib");
        Require(File.Exists(referencePath), $"ML-DSA-87 reference adapter is missing: {referencePath}");
        using var reference = new Mldsa87Reference(referencePath);
        (byte[] publicKey, byte[] privateKey) = reference.GenerateKeyPair();
        byte[] message = Sha3_512Compat.HashData("Keep Vault ML-DSA-87 FIPS 204 interoperability"u8);
        byte[] managedSignature = Mldsa87.Sign(message, privateKey);
        byte[] referenceSignature = reference.Sign(message, privateKey);
        try
        {
            Require(publicKey.Length == Mldsa87.PublicKeyBytes, "ML-DSA-87 public-key length mismatch.");
            Require(privateKey.Length == Mldsa87.PrivateKeyBytes, "ML-DSA-87 private-key length mismatch.");
            Require(managedSignature.Length == Mldsa87.SignatureBytes, "ML-DSA-87 signature length mismatch.");
            Require(reference.Verify(message, managedSignature, publicKey), "Official reference rejected the managed ML-DSA signature.");
            Require(Mldsa87.Verify(message, referenceSignature, publicKey), "Managed verifier rejected the official ML-DSA signature.");

            byte[] changedMessage = message.ToArray();
            byte[] changedSignature = managedSignature.ToArray();
            byte[] changedKey = publicKey.ToArray();
            try
            {
                changedMessage[0] ^= 0x80;
                changedSignature[changedSignature.Length / 2] ^= 0x01;
                changedKey[^1] ^= 0x01;
                Require(!reference.Verify(changedMessage, managedSignature, publicKey), "ML-DSA accepted a changed message.");
                Require(!reference.Verify(message, changedSignature, publicKey), "ML-DSA accepted a changed signature.");
                Require(!Mldsa87.Verify(message, managedSignature, changedKey), "ML-DSA accepted a changed public key.");
            }
            finally
            {
                Zero(changedMessage, changedSignature, changedKey);
            }

            byte[] secondSignature = Mldsa87.Sign(message, privateKey);
            try
            {
                Require(!FixedEqual(managedSignature, secondSignature), "Hedged ML-DSA signing reused identical randomness.");
                Require(reference.Verify(message, secondSignature, publicKey), "Official reference rejected a second hedged signature.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secondSignature);
            }
        }
        finally
        {
            Zero(publicKey, privateKey, message, managedSignature, referenceSignature);
        }

        return Task.CompletedTask;
    }

    private static Task TestArgon2Async()
    {
        Require(NativeArgon2id.IsAvailable(), "Signed fixed-profile Argon2id adapter is unavailable.");
        byte[] password = Enumerable.Range(0, 128).Select(value => (byte)((value * 37) ^ 0xA5)).ToArray();
        byte[] salt = Enumerable.Range(0, 64).Select(value => (byte)(value + 1)).ToArray();
        byte[] native = new byte[64];
        byte[] independent = [];
        long lockedBaseline = SecureMemory.LockedBytesForTests;
        try
        {
            // The PHC adapter runs with ARGON2_FLAG_CLEAR_PASSWORD, so the
            // reference wipes the password buffer it was handed. Keep a copy
            // for the independent implementation, and assert the wipe happened
            // rather than quietly working around it.
            byte[] passwordCopy = password.ToArray();
            NativeArgon2id.HashRaw(
                Argon2Profile.DefaultIterations,
                Argon2Profile.DefaultMemoryKiB,
                Argon2Profile.DefaultParallelism,
                password,
                salt,
                native);
            Require(
                password.All(value => value == 0),
                "Argon2id did not wipe the password buffer it was given.");
            try
            {
                independent = BouncyArgon2(passwordCopy, salt, native.Length);
                Require(FixedEqual(native, independent), "Fixed 1 GiB Argon2id output differs from independent Bouncy Castle.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordCopy);
            }
            Require(SecureMemory.LockedBytesForTests == lockedBaseline, "Argon2id left secure-memory lock accounting behind.");

            bool reducedRejected = false;
            try
            {
                NativeArgon2id.HashRaw(1, 8192, 1, password, salt, new byte[64]);
            }
            catch (CryptographicException)
            {
                reducedRejected = true;
            }

            Require(reducedRejected, "Native Argon2 adapter accepted a reduced profile.");
            RequireThrows<ArgumentOutOfRangeException>(
                () => PasswordKeyService.ValidateArgon2Profile(new Argon2Profile(8192, 1, 1)),
                "Managed KDF accepted a reduced Argon2 profile.");
        }
        finally
        {
            Zero(password, salt, native, independent);
        }

        return Task.CompletedTask;
    }

    private static async Task TestZpaqAsync()
    {
        string root = CreateTempRoot("keep-vault-zpaq-full-");
        try
        {
            string source = Path.Combine(root, "compression-source.bin");
            byte[] bytes = new byte[192 * 1024];
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = (byte)((index * 31) ^ (index >> 7));
            }

            await File.WriteAllBytesAsync(source, bytes).ConfigureAwait(false);
            byte[] expectedHash = Sha3_512Compat.HashData(bytes);
            CryptographicOperations.ZeroMemory(bytes);
            try
            {
                var zpaq = new ZpaqService();
                var integrity = new ArchiveIntegrityService();
                for (int level = 0; level <= 5; level++)
                {
                    string archive = Path.Combine(root, $"level-{level}.zpaq");
                    string output = Path.Combine(root, $"level-{level}-out");
                    ProcessResult add = await zpaq.AddAsync(archive, new[] { source }, level, null, CancellationToken.None).ConfigureAwait(false);
                    Require(add.Succeeded, $"ZPAQ file-mode compression level {level} failed: {add.StandardError}");
                    Require(File.Exists(archive + ".sha3") && File.Exists(archive + ".skein"), $"ZPAQ level {level} omitted dual manifests.");
                    await integrity.VerifyAsync(archive, CancellationToken.None).ConfigureAwait(false);
                    ProcessResult extract = await zpaq.ExtractAsync(archive, output, null, CancellationToken.None).ConfigureAwait(false);
                    Require(extract.Succeeded, $"ZPAQ file-mode extraction level {level} failed: {extract.StandardError}");
                    await RequireFileHashAsync(Path.Combine(output, Path.GetFileName(source)), expectedHash, $"ZPAQ level {level}").ConfigureAwait(false);

                    using var streamArchive = new MemoryStream();
                    ProcessResult streamAdd = await zpaq.AddStreamingAsync(
                        new[] { source },
                        level,
                        (input, cancellationToken) => input.CopyToAsync(streamArchive, cancellationToken),
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    Require(streamAdd.Succeeded && streamArchive.Length > 0, $"ZPAQ streaming compression level {level} failed.");
                    byte[] encoded = streamArchive.ToArray();
                    try
                    {
                        string streamOutput = Path.Combine(root, $"stream-{level}-out");
                        ProcessResult streamExtract = await zpaq.ExtractStreamingAsync(
                            (destination, cancellationToken) => destination.WriteAsync(encoded, cancellationToken).AsTask(),
                            streamOutput,
                            null,
                            CancellationToken.None).ConfigureAwait(false);
                        Require(streamExtract.Succeeded, $"ZPAQ streaming extraction level {level} failed: {streamExtract.StandardError}");
                        await RequireFileHashAsync(Path.Combine(streamOutput, Path.GetFileName(source)), expectedHash, $"streaming ZPAQ level {level}").ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encoded);
                    }
                }

                string damaged = Path.Combine(root, "damaged.zpaq");
                File.Copy(Path.Combine(root, "level-1.zpaq"), damaged);
                File.Copy(Path.Combine(root, "level-1.zpaq.sha3"), damaged + ".sha3");
                File.Copy(Path.Combine(root, "level-1.zpaq.skein"), damaged + ".skein");
                FlipByte(damaged, new FileInfo(damaged).Length - 1);
                await RequireThrowsAsync<InvalidDataException>(
                    () => integrity.VerifyAsync(damaged, CancellationToken.None),
                    "A changed ZPAQ archive passed dual-manifest verification.").ConfigureAwait(false);

                await TestZpaqTraversalAsync(root).ConfigureAwait(false);
                await TestMalformedZpaqCorpusAsync(source, root).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedHash);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestZpaqTraversalAsync(string root)
    {
        string build = Path.Combine(root, "traversal-build");
        string sub = Path.Combine(build, "sub");
        Directory.CreateDirectory(sub);
        await File.WriteAllTextAsync(Path.Combine(build, "payload.txt"), "must not escape").ConfigureAwait(false);
        string executable = ResolveSignedComponent("zpaq.exe");
        using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(executable);
        ProcessResult add = await RunProcessAsync(lease.Path, new[] { "add", "evil.zpaq", "../payload.txt", "-m0" }, sub).ConfigureAwait(false);
        Require(add.Succeeded, $"Could not construct traversal regression archive: {add.StandardError}");
        string archive = Path.Combine(sub, "evil.zpaq");
        await new ArchiveIntegrityService().CreateAsync(archive, CancellationToken.None).ConfigureAwait(false);
        string output = Path.Combine(root, "traversal-output");
        ProcessResult extract = await new ZpaqService().ExtractAsync(archive, output, null, CancellationToken.None).ConfigureAwait(false);
        Require(!extract.Succeeded, "ZPAQ extracted an unsafe ../ archive member.");
        Require(extract.StandardError.Contains("unsafe archive member path", StringComparison.OrdinalIgnoreCase), "ZPAQ did not diagnose the unsafe member.");
        Require(!File.Exists(Path.Combine(root, "payload.txt")), "Traversal archive wrote outside extraction staging.");
        Require(!Directory.Exists(output), "Failed traversal extraction left its destination behind.");
    }

    private static async Task TestMalformedZpaqCorpusAsync(string source, string root)
    {
        using var seedStream = new MemoryStream();
        ProcessResult add = await new ZpaqService().AddStreamingAsync(
            new[] { source },
            0,
            (archive, cancellationToken) => archive.CopyToAsync(seedStream, cancellationToken),
            null,
            CancellationToken.None).ConfigureAwait(false);
        Require(add.Succeeded && seedStream.Length > 64, "Malformed-corpus seed archive was not created.");
        byte[] seed = seedStream.ToArray();
        var corpus = new List<byte[]>();
        int[] lengths = [0, 1, 2, 3, 4, 7, 16, 31, 63, seed.Length / 4, seed.Length / 2, seed.Length - 1];
        corpus.AddRange(lengths.Select(length => seed[..Math.Clamp(length, 0, seed.Length)]));
#pragma warning disable CA5394
        var random = new Random(0x4B5A5041);
        for (int caseIndex = 0; caseIndex < 36; caseIndex++)
        {
            byte[] changed = seed.ToArray();
            for (int mutation = 0; mutation < 1 + (caseIndex % 8); mutation++)
            {
                int offset = random.Next(changed.Length);
                changed[offset] ^= (byte)(1 << random.Next(8));
            }

            corpus.Add(changed);
        }
#pragma warning restore CA5394

        string executable = ResolveSignedComponent("zpaq.exe");
        using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(executable);
        try
        {
            foreach (byte[] input in corpus)
            {
                try
                {
                    await RunMalformedZpaqCaseAsync(lease.Path, input, root).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(input);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static async Task RunMalformedZpaqCaseAsync(string executable, byte[] input, string root)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("--pipe");
        start.ArgumentList.Add("list");
        start.ArgumentList.Add("-");
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("Could not start ZPAQ parser corpus case.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(input).ConfigureAwait(false);
        }
        catch (IOException) when (process.HasExited)
        {
        }
        finally
        {
            process.StandardInput.Close();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw new TimeoutException("Malformed ZPAQ corpus case hung for more than three seconds.");
        }

        await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        Require(process.ExitCode is >= 0 and <= 255, $"Malformed ZPAQ input ended abnormally: {process.ExitCode}");
    }

    private static async Task TestContainersAsync()
    {
        string root = CreateTempRoot("keep-vault-container-full-");
        try
        {
            string source = Path.Combine(root, "source.bin");
            byte[] sourceBytes = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 137);
            await File.WriteAllBytesAsync(source, sourceBytes).ConfigureAwait(false);
            using var zpaqBytes = new MemoryStream();
            ProcessResult zpaqResult = await new ZpaqService().AddStreamingAsync(
                new[] { source },
                1,
                (stream, cancellationToken) => stream.CopyToAsync(zpaqBytes, cancellationToken),
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(zpaqResult.Succeeded, "Container test could not create its ZPAQ payload.");
            byte[] payload = zpaqBytes.ToArray();
            try
            {
                foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
                {
                    await TestContainerSuiteAsync(root, payload, suite).ConfigureAwait(false);
                }
            }
            finally
            {
                Zero(sourceBytes, payload);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestContainerSuiteAsync(string root, byte[] payload, EncryptionSuite suite)
    {
        var containers = new KalynaContainerService();
        AddMouseSamplesUntilReady();
        using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
        string factorA = entropy.FirstPassword;
        string factorB = entropy.SecondPassword;
        string path = Path.Combine(root, $"{suite}.kzpaq");
        Stream source = suite == EncryptionSuite.Kalyna512_512
            ? new ShortReadStream(payload, 97)
            : new MemoryStream(payload, writable: false);
        await using (source.ConfigureAwait(false))
        {
            await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                source,
                path,
                UserPassword,
                factorA,
                factorB,
                suite,
                entropy,
                "full-test",
                null,
                CancellationToken.None).ConfigureAwait(false);
        }

        Require(!entropy.HasPendingEncryptionParameters, $"{suite} did not consume prepared entropy exactly once.");
        ValidateContainerHeader(path, suite);
        KalynaContainerInfo info = await containers.ReadContainerInfoAsync(path, CancellationToken.None).ConfigureAwait(false);
        Require(info.Version == 7 && info.Suite == suite && info.GeneratedPasswordFactorCount == 2 && info.GeneratedPasswordBits == 1024, $"{suite} v7 header metadata mismatch.");

        using var output = new MemoryStream();
        await containers.DecryptToStreamAsync(path, UserPassword, factorA, factorB, output, null, CancellationToken.None).ConfigureAwait(false);
        byte[] decrypted = output.ToArray();
        try
        {
            Require(FixedEqual(payload, decrypted), $"{suite} container roundtrip changed the ZPAQ payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }

        await RequireAuthenticationFailureWithoutOutputAsync(
            containers,
            path,
            WrongPassword,
            factorA,
            factorB,
            $"{suite} wrong user password").ConfigureAwait(false);
        await RequireAuthenticationFailureWithoutOutputAsync(
            containers,
            path,
            UserPassword,
            GeneratedFactor('C'),
            factorB,
            $"{suite} wrong factor A").ConfigureAwait(false);

        string nonCanonical = CopyContainer(path, root, $"{suite}-noncanonical.kzpaq");
        AddHeaderWhitespace(nonCanonical);
        await RequireThrowsAsync<InvalidDataException>(
            () => containers.ReadContainerInfoAsync(nonCanonical, CancellationToken.None),
            $"{suite} accepted noncanonical header JSON.").ConfigureAwait(false);

        string reducedProfile = CopyContainer(path, root, $"{suite}-reduced-profile.kzpaq");
        ReplaceHeaderToken(reducedProfile, "\"Argon2Iterations\":4", "\"Argon2Iterations\":1");
        await RequireThrowsAsync<InvalidDataException>(
            () => containers.ReadContainerInfoAsync(reducedProfile, CancellationToken.None),
            $"{suite} accepted a reduced Argon2 profile.").ConfigureAwait(false);

        if (suite == EncryptionSuite.Threefish1024)
        {
            foreach ((string label, Action<string> mutate, Type expected) in new[]
            {
                ("magic", new Action<string>(candidate => FlipByte(candidate, 0)), typeof(InvalidDataException)),
                ("SHA3 tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: false)), typeof(CryptographicException)),
                ("Skein tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: true)), typeof(CryptographicException)),
                ("ciphertext", new Action<string>(candidate => FlipByte(candidate, new FileInfo(candidate).Length - 1)), typeof(CryptographicException)),
            })
            {
                string candidate = CopyContainer(path, root, $"Threefish-{label.Replace(' ', '-')}.kzpaq");
                mutate(candidate);
                await RequireFailureWithoutOutputAsync(
                    containers,
                    candidate,
                    UserPassword,
                    factorA,
                    factorB,
                    expected,
                    $"Threefish changed {label}").ConfigureAwait(false);
            }
        }

        string existing = Path.Combine(root, $"{suite}-existing.kzpaq");
        byte[] sentinel = "existing target survives"u8.ToArray();
        await File.WriteAllBytesAsync(existing, sentinel).ConfigureAwait(false);
        try
        {
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy rejectedEntropy = EntropyMixer.CreateArchiveEntropy();
            await RequireThrowsAsync<IOException>(
                async () =>
                {
                    await using var tiny = new MemoryStream([1, 2, 3, 4], writable: false);
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        tiny,
                        existing,
                        UserPassword,
                        rejectedEntropy.FirstPassword,
                        rejectedEntropy.SecondPassword,
                        suite,
                        rejectedEntropy,
                        null,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                },
                $"{suite} overwrote an existing encrypted target.").ConfigureAwait(false);
            byte[] after = await File.ReadAllBytesAsync(existing).ConfigureAwait(false);
            try
            {
                Require(FixedEqual(sentinel, after), $"{suite} modified an existing output after refusal.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(after);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sentinel);
        }
    }

    private static async Task TestRecoveryAsync()
    {
        string root = CreateTempRoot("keep-vault-kpar2-full-");
        try
        {
            var recovery = new RecoveryService();
            string plain = Path.Combine(root, "plain.zpaq");
            byte[] plainBytes = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 333);
            byte[] plainHash = Sha3_512Compat.HashData(plainBytes);
            await File.WriteAllBytesAsync(plain, plainBytes).ConfigureAwait(false);
            string sidecar = await recovery.CreateAsync(plain, null, CancellationToken.None).ConfigureAwait(false);
            Require(File.Exists(sidecar), "Plain KPAR2-v2 sidecar was not created.");
            Require(await recovery.TryReadProtectionModeAsync(plain, CancellationToken.None).ConfigureAwait(false) == RecoveryProtectionMode.ErrorCorrectionOnly, "Plain KPAR2 protection mode mismatch.");
            FlipRange(plain, 0, 4096);
            byte[] damagedHash = await HashFileAsync(plain).ConfigureAwait(false);
            RecoveryRepairResult repaired = await recovery.VerifyAndRepairAsync(plain, null, CancellationToken.None).ConfigureAwait(false);
            Require(repaired.Repaired && repaired.OutputPath is not null, "Plain KPAR2 did not create a repair candidate.");
            byte[] repairedHash = await HashFileAsync(repaired.OutputPath!).ConfigureAwait(false);
            byte[] originalAfter = await HashFileAsync(plain).ConfigureAwait(false);
            try
            {
                Require(FixedEqual(plainHash, repairedHash), "Plain KPAR2 repair did not reconstruct exact bytes.");
                Require(FixedEqual(damagedHash, originalAfter), "Plain KPAR2 modified the damaged original.");
            }
            finally
            {
                Zero(plainBytes, plainHash, damagedHash, repairedHash, originalAfter);
            }

            string encrypted = Path.Combine(root, "authenticated.kzpaq");
            byte[] payload = RandomNumberGenerator.GetBytes((1024 * 1024) + 71);
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            string factorA = entropy.FirstPassword;
            string factorB = entropy.SecondPassword;
            var containers = new KalynaContainerService();
            await using (var input = new MemoryStream(payload, writable: false))
            {
                await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                    input,
                    encrypted,
                    UserPassword,
                    factorA,
                    factorB,
                    EncryptionSuite.Threefish1024,
                    entropy,
                    null,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            byte[] encryptedHash = await HashFileAsync(encrypted).ConfigureAwait(false);
            string authenticatedSidecar = await recovery.CreateAuthenticatedAsync(
                encrypted,
                UserPassword,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(await recovery.TryReadProtectionModeAsync(encrypted, CancellationToken.None).ConfigureAwait(false) == RecoveryProtectionMode.DualAuthenticatedEncrypted, "Encrypted KPAR2 is not marked dual authenticated.");

            string transplant = Path.Combine(root, "transplant.kzpaq");
            byte[] transplantBytes = RandomNumberGenerator.GetBytes(checked((int)new FileInfo(encrypted).Length));
            await File.WriteAllBytesAsync(transplant, transplantBytes).ConfigureAwait(false);
            byte[] transplantHash = Sha3_512Compat.HashData(transplantBytes);
            File.Copy(authenticatedSidecar, RecoveryService.GetRecoveryPath(transplant));
            await RequireThrowsAsync<InvalidDataException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(transplant, UserPassword, factorA, factorB, null, CancellationToken.None),
                "Authenticated KPAR2 sidecar transplantation was accepted.").ConfigureAwait(false);
            byte[] transplantAfter = await HashFileAsync(transplant).ConfigureAwait(false);
            Require(FixedEqual(transplantHash, transplantAfter), "Rejected KPAR2 transplant modified its target.");

            FlipRange(encrypted, 0, 4096);
            byte[] damagedEncryptedHash = await HashFileAsync(encrypted).ConfigureAwait(false);
            await RequireThrowsAsync<CryptographicException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(encrypted, WrongPassword, factorA, factorB, null, CancellationToken.None),
                "Wrong password authenticated KPAR2 metadata.").ConfigureAwait(false);
            byte[] afterWrongPassword = await HashFileAsync(encrypted).ConfigureAwait(false);
            Require(FixedEqual(damagedEncryptedHash, afterWrongPassword), "Wrong-password KPAR2 attempt modified the original.");

            RecoveryRepairResult authenticatedRepair = await recovery.VerifyAndRepairAuthenticatedAsync(
                encrypted,
                UserPassword,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(authenticatedRepair.Repaired && authenticatedRepair.Authenticated && authenticatedRepair.OutputPath is not null, "Authenticated KPAR2 did not emit a verified repair candidate.");
            byte[] authenticatedHash = await HashFileAsync(authenticatedRepair.OutputPath!).ConfigureAwait(false);
            Require(FixedEqual(encryptedHash, authenticatedHash), "Authenticated KPAR2 did not restore exact container bytes.");
            using var decrypted = new MemoryStream();
            await containers.DecryptToStreamAsync(authenticatedRepair.OutputPath!, UserPassword, factorA, factorB, decrypted, null, CancellationToken.None).ConfigureAwait(false);
            byte[] recoveredPayload = decrypted.ToArray();
            Require(FixedEqual(payload, recoveredPayload), "KPAR2-recovered container failed dual-MAC decryption.");

            Zero(payload, encryptedHash, transplantBytes, transplantHash, transplantAfter, damagedEncryptedHash, afterWrongPassword, authenticatedHash, recoveredPayload);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestCryptographicEraseAsync()
    {
        string root = CreateTempRoot("keep-vault-erase-full-");
        try
        {
            string container = Path.Combine(root, "erase.kzpaq");
            byte[] payload = RandomNumberGenerator.GetBytes(128 * 1024);
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            string factorA = entropy.FirstPassword;
            string factorB = entropy.SecondPassword;
            await using (var input = new MemoryStream(payload, writable: false))
            {
                await new KalynaContainerService().EncryptZpaqStreamWithPreparedEntropyAsync(
                    input,
                    container,
                    UserPassword,
                    factorA,
                    factorB,
                    EncryptionSuite.Threefish1024,
                    entropy,
                    null,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            string sidecar = await new RecoveryService().CreateAuthenticatedAsync(
                container,
                UserPassword,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            var erase = new CryptographicEraseService();
            CryptoEraseAnalysis analysis = await erase.AnalyzeAsync(container, CancellationToken.None).ConfigureAwait(false);
            Require(analysis.Exists && analysis.IsEncryptedContainer, "Valid v7 container was not classified as cryptographically erasable.");
            Require(analysis.HardwareNotice.Contains("SSD", StringComparison.Ordinal), "Erase analysis hides the SSD remanence limitation.");

            string hardLink = Path.Combine(root, "hardlink.kzpaq");
            Require(MacTestLinks.CreateHardLink(container, hardLink) == 0, "Could not create hard-link erase fixture.");
            await RequireThrowsAsync<IOException>(
                () => erase.EraseEncryptedContainerAsync(container, null, CancellationToken.None),
                "Cryptographic erase accepted a multiply-linked container.").ConfigureAwait(false);
            Require(File.Exists(container) && File.Exists(hardLink) && File.Exists(sidecar), "Hard-link refusal did not preserve container and recovery data.");
            File.Delete(hardLink);

            CryptoEraseResult result = await erase.EraseEncryptedContainerAsync(container, null, CancellationToken.None).ConfigureAwait(false);
            Require(result.Deleted, "Cryptographic erase did not report success.");
            Require(!File.Exists(container), "Cryptographic erase left the encrypted container.");
            Require(!File.Exists(sidecar), "Cryptographic erase left recoverable KPAR2 data.");
            CryptographicOperations.ZeroMemory(payload);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void ValidateContainerHeader(string path, EncryptionSuite suite)
    {
        using FileStream input = File.OpenRead(path);
        byte[] magic = new byte[7];
        input.ReadExactly(magic);
        Require(FixedEqual(magic, "KZPAQ1\0"u8), "Container magic mismatch.");
        Span<byte> lengthBytes = stackalloc byte[4];
        input.ReadExactly(lengthBytes);
        int length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
        Require(length is > 0 and <= 16 * 1024, "Container header length is unbounded.");
        byte[] headerBytes = new byte[length];
        input.ReadExactly(headerBytes);
        try
        {
            using JsonDocument document = JsonDocument.Parse(headerBytes);
            JsonElement header = document.RootElement;
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
            Require(header.GetProperty("Version").GetInt32() == 7, "Container version is not v7.");
            Require(header.GetProperty("Algorithm").GetString() == parameters.Algorithm, "Container algorithm label mismatch.");
            Require(header.GetProperty("CounterEndian").GetString() == EncryptionSuiteCatalog.CounterEndian, "Container counter endian mismatch.");
            Require(header.GetProperty("Argon2MemoryKiB").GetInt32() == Argon2Profile.DefaultMemoryKiB, "Container Argon2 memory is not 1 GiB.");
            Require(header.GetProperty("Argon2Iterations").GetInt32() == Argon2Profile.DefaultIterations, "Container Argon2 iterations mismatch.");
            Require(header.GetProperty("Argon2Parallelism").GetInt32() == Argon2Profile.DefaultParallelism, "Container Argon2 parallelism mismatch.");
            Require(header.GetProperty("GeneratedPasswordFactorCount").GetInt32() == 2, "Container factor count mismatch.");
            Require(header.GetProperty("GeneratedPasswordBits").GetInt32() == 1024, "Container generated-factor bits mismatch.");
            Require(input.Length - input.Position > 64 + 128, "Container lacks two tags and ciphertext.");
        }
        finally
        {
            Zero(magic, headerBytes);
        }
    }

    private static async Task RequireAuthenticationFailureWithoutOutputAsync(
        KalynaContainerService service,
        string path,
        string password,
        string factorA,
        string factorB,
        string label)
    {
        await RequireFailureWithoutOutputAsync(
            service,
            path,
            password,
            factorA,
            factorB,
            typeof(CryptographicException),
            label).ConfigureAwait(false);
    }

    private static async Task RequireFailureWithoutOutputAsync(
        KalynaContainerService service,
        string path,
        string password,
        string factorA,
        string factorB,
        Type expectedException,
        string label)
    {
        byte[] sentinel = "destination-must-remain-unchanged"u8.ToArray();
        using var output = new MemoryStream();
        output.Write(sentinel);
        try
        {
            await service.DecryptToStreamAsync(path, password, factorA, factorB, output, null, CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException($"{label} unexpectedly decrypted.");
        }
        catch (Exception ex) when (ex.GetType() == expectedException)
        {
        }

        byte[] after = output.ToArray();
        try
        {
            Require(FixedEqual(sentinel, after), $"{label} emitted plaintext before authentication.");
        }
        finally
        {
            Zero(sentinel, after);
        }
    }

    private static byte[] BouncyArgon2(byte[] password, byte[] salt, int outputLength)
    {
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(Argon2Profile.DefaultMemoryKiB)
            .WithIterations(Argon2Profile.DefaultIterations)
            .WithParallelism(Argon2Profile.DefaultParallelism)
            .WithSalt(salt.ToArray())
            .Build();
        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        byte[] output = new byte[outputLength];
        Require(generator.GenerateBytes(password, output) == outputLength, "Independent Argon2 output length mismatch.");
        return output;
    }

    private static byte[] BouncySkeinMac(byte[] key, byte[] data)
    {
        var mac = new SkeinMac(1024, 1024);
        mac.Init(new KeyParameter(key.ToArray()));
        mac.BlockUpdate(data);
        byte[] output = new byte[128];
        mac.DoFinal(output);
        return output;
    }

    private static void SerialKalyna(byte[] key, byte[] nonce, byte[] input, byte[] output)
    {
        byte[] counter = nonce.ToArray();
        try
        {
            for (int offset = 0; offset < input.Length; offset += 256 * 1024)
            {
                int count = Math.Min(256 * 1024, input.Length - offset);
                byte[] source = input.AsSpan(offset, count).ToArray();
                byte[] target = new byte[count];
                try
                {
                    NativeKalyna.XCryptCtr512(key, counter, source, target, count);
                    target.CopyTo(output, offset);
                    IncrementCounter(counter, (count + 63L) / 64L);
                }
                finally
                {
                    Zero(source, target);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }
    }

    private static void SerialThreefish(byte[] key, byte[] tweak, byte[] nonce, byte[] input, byte[] output)
    {
        byte[] counter = nonce.ToArray();
        try
        {
            for (int offset = 0; offset < input.Length; offset += 256 * 1024)
            {
                int count = Math.Min(256 * 1024, input.Length - offset);
                byte[] source = input.AsSpan(offset, count).ToArray();
                byte[] target = new byte[count];
                try
                {
                    NativeThreefish.XCryptCtr1024(key, tweak, counter, source, target, count);
                    target.CopyTo(output, offset);
                    IncrementCounter(counter, (count + 127L) / 128L);
                }
                finally
                {
                    Zero(source, target);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }
    }

    private static void IncrementCounter(byte[] counter, long blocks)
    {
        ulong carry = checked((ulong)blocks);
        for (int index = counter.Length - 1; index >= 0 && carry != 0; index--)
        {
            ulong sum = counter[index] + (carry & 0xFF);
            counter[index] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }

        Require(carry == 0, "Test CTR counter overflowed.");
    }

    private static void AddMouseSamplesUntilReady()
    {
        int index = 0;
        while (!EntropyMixer.HasRequiredSamples(EntropyPurpose.GeneratedPasswordFirst)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.GeneratedPasswordSecond)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.Salt)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.NonceFirst)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.NonceSecond))
        {
            EntropyMixer.AddMouseSample(
                100.125 + (index * 0.003),
                200.875 + (index * 0.007),
                Environment.TickCount ^ index,
                (index & 1) != 0,
                (index & 2) != 0,
                (index & 4) != 0);
            index++;
        }
    }

    private static string GeneratedFactor(char value) => new(value, PasswordKeyService.GeneratedPasswordLength);

    private static string CreateTempRoot(string prefix)
    {
        string path = Directory.CreateTempSubdirectory(prefix).FullName;
        string canonical = MacSafeFileSystem.ResolveExistingRealPath(path);
        File.SetUnixFileMode(canonical, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return canonical;
    }

    private static string CopyContainer(string source, string root, string name)
    {
        string target = Path.Combine(root, name);
        File.Copy(source, target);
        return target;
    }

    private static void AddHeaderWhitespace(string path)
    {
        byte[] file = File.ReadAllBytes(path);
        byte[]? changed = null;
        try
        {
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(7, 4));
            int headerOffset = 11;
            Require(headerLength > 0 && headerOffset + headerLength <= file.Length, "Mutation fixture header is invalid.");
            changed = new byte[file.Length + 1];
            file.AsSpan(0, headerOffset + 1).CopyTo(changed);
            changed[headerOffset + 1] = (byte)' ';
            file.AsSpan(headerOffset + 1).CopyTo(changed.AsSpan(headerOffset + 2));
            BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(7, 4), headerLength + 1);
            File.WriteAllBytes(path, changed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file);
            if (changed is not null) CryptographicOperations.ZeroMemory(changed);
        }
    }

    private static void ReplaceHeaderToken(string path, string oldToken, string newToken)
    {
        byte[] file = File.ReadAllBytes(path);
        byte[]? replacement = null;
        try
        {
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(7, 4));
            const int headerOffset = 11;
            string header = Encoding.UTF8.GetString(file, headerOffset, headerLength);
            Require(header.CountOccurrences(oldToken) == 1, $"Header mutation token is not unique: {oldToken}");
            byte[] nextHeader = Encoding.UTF8.GetBytes(header.Replace(oldToken, newToken, StringComparison.Ordinal));
            try
            {
                int suffix = headerOffset + headerLength;
                replacement = new byte[headerOffset + nextHeader.Length + file.Length - suffix];
                file.AsSpan(0, 7).CopyTo(replacement);
                BinaryPrimitives.WriteInt32LittleEndian(replacement.AsSpan(7, 4), nextHeader.Length);
                nextHeader.CopyTo(replacement.AsSpan(headerOffset));
                file.AsSpan(suffix).CopyTo(replacement.AsSpan(headerOffset + nextHeader.Length));
                File.WriteAllBytes(path, replacement);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nextHeader);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file);
            if (replacement is not null) CryptographicOperations.ZeroMemory(replacement);
        }
    }

    private static void FlipContainerTag(string path, bool skein)
    {
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Span<byte> headerLength = stackalloc byte[4];
        stream.Position = 7;
        stream.ReadExactly(headerLength);
        long offset = 11L + BinaryPrimitives.ReadInt32LittleEndian(headerLength) + (skein ? 64 : 0);
        stream.Position = offset;
        int value = stream.ReadByte();
        Require(value >= 0, "Authentication-tag mutation offset is invalid.");
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
        stream.Flush(flushToDisk: true);
    }

    private static void FlipRange(string path, long offset, int length)
    {
        byte[] changed = RandomNumberGenerator.GetBytes(length);
        try
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            stream.Position = offset;
            stream.Write(changed);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(changed);
        }
    }

    private static void FlipByte(string path, long offset)
    {
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = offset;
        int value = stream.ReadByte();
        Require(value >= 0, "Mutation offset is outside the file.");
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
        stream.Flush(flushToDisk: true);
    }

    private static async Task<byte[]> HashFileAsync(string path)
    {
        await using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
        var digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512);
        byte[] buffer = new byte[1024 * 1024];
        byte[] output = new byte[64];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
            {
                digest.BlockUpdate(buffer, 0, read);
            }

            digest.DoFinal(output, 0);
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static async Task RequireFileHashAsync(string path, byte[] expected, string label)
    {
        byte[] actual = await HashFileAsync(path).ConfigureAwait(false);
        try
        {
            Require(FixedEqual(expected, actual), $"{label} content hash mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task<ProcessResult> RunProcessAsync(string executable, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {executable}.");
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new ProcessResult(process.ExitCode, stdout, stderr);
    }

    private static byte[] WordsToLittleEndian(ulong[] words)
    {
        byte[] bytes = new byte[words.Length * sizeof(ulong)];
        for (int index = 0; index < words.Length; index++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(index * sizeof(ulong)), words[index]);
        }

        return bytes;
    }

    private static bool FixedEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void RequireHex(byte[] actual, string expected, string label)
    {
        try
        {
            Require(string.Equals(Convert.ToHexString(actual), expected, StringComparison.Ordinal), $"{label} mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static void Zero(params byte[][] arrays)
    {
        foreach (byte[] array in arrays) CryptographicOperations.ZeroMemory(array);
    }

    internal static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void RequireThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static async Task RequireThrowsAsync<TException>(Func<Task> action, string message)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private sealed class ShortReadStream(byte[] data, int maxRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = Math.Min(Math.Min(buffer.Length, maxRead), data.Length - _position);
            if (count <= 0) return ValueTask.FromResult(0);
            data.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int actual = Math.Min(Math.Min(count, maxRead), data.Length - _position);
            if (actual <= 0) return 0;
            Buffer.BlockCopy(data, _position, buffer, offset, actual);
            _position += actual;
            return actual;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static partial class MacTestLinks
    {
        [System.Runtime.InteropServices.LibraryImport("libSystem.B.dylib", EntryPoint = "link", SetLastError = true, StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf8)]
        internal static partial int CreateHardLink(string existingPath, string newPath);
    }
}

file static class StringTestExtensions
{
    internal static int CountOccurrences(this string value, string token)
    {
        int count = 0;
        int offset = 0;
        while ((offset = value.IndexOf(token, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += token.Length;
        }

        return count;
    }
}
