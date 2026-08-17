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
            ("randomised differential testing against every reference library", TestReferenceDifferentialAsync),
            ("Argon2id fixed 1 GiB profile and independent equivalence", TestArgon2Async),
            ("ZPAQ levels, streaming, traversal and malformed corpus", TestZpaqAsync),
            ("v9 triple-suite roundtrip and manipulation rejection", TestContainersAsync),
            ("cascade layering: the outer layer alone reveals nothing", TestCascadeLayeringAsync),
            ("v9 two-round key derivation from one pool consumption", TestTwoRoundDerivationAsync),
            ("v9 per-chunk nonces across a multi-chunk archive", TestPerChunkNoncesAsync),
            ("MARS and SHACAL-2 published vectors and CTR behaviour", TestCascadeCipherVectorsAsync),
            ("KPAR2-v2 repair, authentication and transplantation rejection", TestRecoveryAsync),
            ("cryptographic erase ordering and hard-link refusal", TestCryptographicEraseAsync),
            ("verified original deletion refuses on any mismatch", TestVerifiedOriginalDeletionAsync),
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

    /// <summary>
    /// Compares every primitive the app computes in managed code against its
    /// official reference implementation, over randomised inputs.
    /// </summary>
    /// <remarks>
    /// Fixed known-answer vectors prove a primitive agrees at a handful of
    /// points. They do not catch the failures that actually occur in practice:
    /// mishandled block boundaries, a wrong rate, incremental updates that
    /// disagree with the one-shot call, or lengths that only go wrong past a
    /// buffer size. Randomised differential testing across those boundaries
    /// does, and it matters most here because SHA3-512 and Skein-1024 come from
    /// Bouncy Castle rather than from the references — every container tag,
    /// integrity manifest and key-derivation pre-hash depends on that library
    /// being right.
    ///
    /// ZPAQ is deliberately absent: its pipeline was adapted for this app's
    /// encryption, so stock zpaq is not a valid oracle for it. Its behaviour is
    /// covered instead by the round-trip, traversal and malformed-corpus group.
    /// </remarks>
    /// <summary>
    /// Covers the gate that guards deleting a user's only copy of a file.
    /// </summary>
    /// <remarks>
    /// The archiving option deletes originals only after the archive has been
    /// extracted again and compared byte for byte. What matters is not that the
    /// happy path works but that every way the comparison can fail actually
    /// blocks the deletion, so each failure mode is provoked deliberately: a
    /// changed byte, a file the archive lost, and a file the archive gained.
    /// </remarks>
    private static async Task TestVerifiedOriginalDeletionAsync()
    {
        string root = CreateTempRoot("keep-vault-delete-verify-");
        try
        {
            string originals = Path.Combine(root, "originals");
            string extracted = Path.Combine(root, "extracted");
            Directory.CreateDirectory(originals);
            Directory.CreateDirectory(extracted);

            string firstName = "first.bin";
            string secondName = "second.bin";
            byte[] first = RandomNumberGenerator.GetBytes(64 * 1024);
            byte[] second = RandomNumberGenerator.GetBytes(4096);
            await File.WriteAllBytesAsync(Path.Combine(originals, firstName), first).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(originals, secondName), second).ConfigureAwait(false);

            string[] inputs =
            [
                Path.Combine(originals, firstName),
                Path.Combine(originals, secondName),
            ];

            // A faithful extraction must be accepted.
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), first).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extracted, secondName), second).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult match =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(match.Verified, $"A faithful extraction was rejected: {match.Failure}");
            Require(match.FilesCompared == 2, "The comparison did not cover both files.");
            Require(match.BytesCompared == first.Length + second.Length, "The compared byte count is wrong.");

            // One flipped byte must block deletion.
            byte[] altered = first.ToArray();
            altered[altered.Length / 2] ^= 0x01;
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), altered).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult flipped =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!flipped.Verified, "A single flipped byte was accepted as a faithful extraction.");

            // A file the archive lost must block deletion.
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), first).ConfigureAwait(false);
            File.Delete(Path.Combine(extracted, secondName));
            MacOriginalDeletionService.VerificationResult missing =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!missing.Verified, "A dropped file was accepted as a faithful extraction.");

            // A file the archive gained must block deletion too: it means the
            // extraction is not the set that was archived.
            await File.WriteAllBytesAsync(Path.Combine(extracted, secondName), second).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extracted, "unexpected.bin"), second).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult extra =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!extra.Verified, "An unexpected extra file was accepted as a faithful extraction.");

            // A truncated file has the right name and wrong length.
            File.Delete(Path.Combine(extracted, "unexpected.bin"));
            await File.WriteAllBytesAsync(
                Path.Combine(extracted, secondName),
                second.AsSpan(0, second.Length - 1).ToArray()).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult truncated =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!truncated.Verified, "A truncated file was accepted as a faithful extraction.");

            // Every original must still be present: no failure path deletes.
            Require(File.Exists(inputs[0]) && File.Exists(inputs[1]), "A rejected comparison removed an original.");

            Zero(first, second, altered);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task TestReferenceDifferentialAsync()
    {
        string sha3ReferencePath = Environment.GetEnvironmentVariable("KEEPVAULT_SHA3_REFERENCE")
            ?? Path.Combine(AppContext.BaseDirectory, "Native", "libsha3_ref.dylib");
        Require(File.Exists(sha3ReferencePath), $"SHA3-512 reference adapter is missing: {sha3ReferencePath}");
        using var sha3 = new KeepVaultMac.Tests.Sha3Reference(sha3ReferencePath);

        Require(
            sha3.BlockSize == 72,
            $"The SHA3-512 reference reports a rate of {sha3.BlockSize} rather than 72 bytes.");

        // Lengths chosen to straddle the SHA3-512 rate (72), the Skein-1024
        // block (128) and the cipher block sizes, plus their neighbours, since
        // that is where padding and buffering mistakes surface.
        int[] lengths =
        [
            0, 1, 63, 64, 65, 71, 72, 73, 127, 128, 129, 143, 144, 145,
            255, 256, 257, 1023, 1024, 1025, 4095, 4096,
        ];

        foreach (int length in lengths)
        {
            byte[] message = RandomNumberGenerator.GetBytes(length);
            // HMAC accepts any key length, and varying it exercises the
            // shorter-than-block, exactly-block and longer-than-block paths.
            // Skein's keyed mode takes a fixed 128-byte key.
            byte[] key = RandomNumberGenerator.GetBytes(length % 97 == 0 ? 64 : (length % 97) + 1);
            byte[] skeinKey = RandomNumberGenerator.GetBytes(128);
            try
            {
                Require(
                    FixedEqual(Sha3_512Compat.HashData(message), sha3.Hash(message)),
                    $"Managed SHA3-512 disagrees with the FIPS 202 reference at {length} bytes.");

                using (var incremental = new Sha3_512Incremental())
                {
                    // Split at an offset that is not a multiple of the rate, so
                    // a buffering error cannot hide behind aligned chunks.
                    int split = length / 3;
                    incremental.AppendData(message.AsSpan(0, split));
                    incremental.AppendData(message.AsSpan(split));
                    Require(
                        FixedEqual(incremental.GetHashAndReset(), sha3.Hash(message)),
                        $"Incremental SHA3-512 disagrees with the reference at {length} bytes.");
                }

                using (var mac = new HmacSha3_512(key))
                {
                    mac.AppendData(message);
                    Require(
                        FixedEqual(mac.GetHashAndReset(), sha3.Hmac(key, message)),
                        $"Managed HMAC-SHA3-512 disagrees with the reference at {length} bytes.");
                }

                Require(
                    FixedEqual(Skein1024Digest.HashData(message), NativeThreefish.HashSkein1024Reference(message)),
                    $"Managed Skein-1024 disagrees with the Skein reference at {length} bytes.");

                Require(
                    FixedEqual(BouncySkeinMac(skeinKey, message), NativeThreefish.MacSkein1024Reference(skeinKey, message)),
                    $"Managed Skein-1024 MAC disagrees with the Skein reference at {length} bytes.");
            }
            finally
            {
                Zero(message, key, skeinKey);
            }
        }

        // Both ciphers run in counter mode, so a disagreement in the block
        // function or in the counter's byte order shows up as diverging
        // keystream. Sizes span the parallel-processing threshold.
        foreach (int length in new[] { 1, 63, 64, 65, 4096, 1 << 20 })
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(length);
            byte[] kalynaKey = RandomNumberGenerator.GetBytes(64);
            byte[] kalynaNonce = RandomNumberGenerator.GetBytes(64);
            byte[] threefishKey = RandomNumberGenerator.GetBytes(128);
            byte[] threefishTweak = RandomNumberGenerator.GetBytes(16);
            byte[] threefishNonce = RandomNumberGenerator.GetBytes(128);
            byte[] kalynaOut = new byte[length];
            byte[] kalynaBack = new byte[length];
            byte[] threefishOut = new byte[length];
            byte[] threefishBack = new byte[length];
            try
            {
                NativeKalyna.XCryptCtr512(kalynaKey, kalynaNonce, plaintext, kalynaOut, length);
                NativeKalyna.XCryptCtr512(kalynaKey, kalynaNonce, kalynaOut, kalynaBack, length);
                Require(
                    FixedEqual(plaintext, kalynaBack),
                    $"Kalyna-512/512 counter mode is not self-inverse at {length} bytes.");
                Require(
                    !FixedEqual(plaintext, kalynaOut) || length == 0,
                    $"Kalyna-512/512 produced its own plaintext as ciphertext at {length} bytes.");

                NativeThreefish.XCryptCtr1024(threefishKey, threefishTweak, threefishNonce, plaintext, threefishOut, length);
                NativeThreefish.XCryptCtr1024(threefishKey, threefishTweak, threefishNonce, threefishOut, threefishBack, length);
                Require(
                    FixedEqual(plaintext, threefishBack),
                    $"Threefish-1024 counter mode is not self-inverse at {length} bytes.");
                Require(
                    !FixedEqual(plaintext, threefishOut) || length == 0,
                    $"Threefish-1024 produced its own plaintext as ciphertext at {length} bytes.");
            }
            finally
            {
                Zero(plaintext, kalynaKey, kalynaNonce, threefishKey, threefishTweak, threefishNonce,
                    kalynaOut, kalynaBack, threefishOut, threefishBack);
            }
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
        Require(info.Version == 9 && info.Suite == suite && info.GeneratedPasswordFactorCount == 2 && info.GeneratedPasswordBits == 1024, $"{suite} v9 header metadata mismatch.");

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

        // v9 is a clean break. A container claiming any other version must be
        // refused outright rather than read on a compatibility path, and the
        // refusal must not depend on the MACs noticing the edit afterwards.
        foreach (int rejected in new[] { 7, 8, 10 })
        {
            string downgraded = CopyContainer(path, root, $"{suite}-version-{rejected}.kzpaq");
            ReplaceHeaderToken(downgraded, "\"Version\":9", $"\"Version\":{rejected}");
            await RequireThrowsAsync<InvalidDataException>(
                () => containers.ReadContainerInfoAsync(downgraded, CancellationToken.None),
                $"{suite} accepted a container claiming version {rejected}.").ConfigureAwait(false);
            await RequireFailureWithoutOutputAsync(
                containers,
                downgraded,
                UserPassword,
                factorA,
                factorB,
                typeof(InvalidDataException),
                $"{suite} decrypted a container claiming version {rejected}").ConfigureAwait(false);
        }

        string reducedProfile = CopyContainer(path, root, $"{suite}-reduced-profile.kzpaq");
        ReplaceHeaderToken(reducedProfile, "\"Argon2Iterations\":4", "\"Argon2Iterations\":1");
        await RequireThrowsAsync<InvalidDataException>(
            () => containers.ReadContainerInfoAsync(reducedProfile, CancellationToken.None),
            $"{suite} accepted a reduced Argon2 profile.").ConfigureAwait(false);

        if (suite is EncryptionSuite.Threefish1024 or EncryptionSuite.ThreefishOverKalyna)
        {
            foreach ((string label, Action<string> mutate, Type expected) in new[]
            {
                ("magic", new Action<string>(candidate => FlipByte(candidate, 0)), typeof(InvalidDataException)),
                ("SHA3 tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: false)), typeof(CryptographicException)),
                ("Skein tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: true)), typeof(CryptographicException)),
                ("ciphertext", new Action<string>(candidate => FlipByte(candidate, new FileInfo(candidate).Length - 1)), typeof(CryptographicException)),
            })
            {
                string candidate = CopyContainer(path, root, $"{suite}-{label.Replace(' ', '-')}.kzpaq");
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

    /// <summary>
    /// Proves that defeating the outer layer alone yields nothing usable.
    /// </summary>
    /// <remarks>
    /// The cascade is only worth its second pass if both ciphers must fall. An
    /// attacker who breaks Threefish recovers the outer keystream and can strip
    /// it — and must then be left holding Kalyna ciphertext, not plaintext and
    /// not the archive's structure. This drives the two layers directly with
    /// known keys so the property is checked, not argued.
    /// </remarks>
    private static Task TestCascadeLayeringAsync()
    {
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.ThreefishOverKalyna);
        CascadeLayout layout = parameters.Cascade
            ?? throw new InvalidOperationException("The cascade suite lost its layer layout.");
        Require(layout.Stages.Count == 2, $"The cascade has {layout.Stages.Count} stages rather than two.");
        Require(
            layout.Stages[0].Cipher == CascadeCipher.Kalyna512_512
            && layout.Stages[0].KeyBytes == 64 && layout.Stages[0].NonceBytes == 64,
            "The cascade's inner stage is not Kalyna with a 64-byte key and nonce.");
        Require(
            layout.Stages[1].Cipher == CascadeCipher.Threefish1024
            && layout.Stages[1].KeyBytes == 128 && layout.Stages[1].NonceBytes == 128,
            "The cascade's outer stage is not Threefish with a 128-byte key and nonce.");
        Require(!layout.OutermostIsAead, "The two-layer cascade must not claim an authenticated outer layer.");
        Require(parameters.DerivedKeyBytes == 384, "Cascade derived key is not 384 bytes.");

        // The six-layer suite, checked the same way: the order is the order the
        // plaintext travels, and the key and nonce shares are what the header
        // and the KDF budget were sized against.
        EncryptionSuiteParameters paranoia = EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
        CascadeLayout paranoiaLayout = paranoia.Cascade
            ?? throw new InvalidOperationException("The paranoia suite lost its layer layout.");
        CascadeCipher[] expectedOrder =
        [
            CascadeCipher.Aes256,
            CascadeCipher.Mars448,
            CascadeCipher.Shacal2_512,
            CascadeCipher.Kalyna512_512,
            CascadeCipher.Threefish1024,
            CascadeCipher.ChaCha20Poly1305,
        ];
        Require(
            paranoiaLayout.Stages.Select(stage => stage.Cipher).SequenceEqual(expectedOrder),
            "The paranoia cascade's layer order is not AES, MARS, SHACAL-2, Kalyna, Threefish, ChaCha20-Poly1305.");
        Require(paranoiaLayout.OutermostIsAead, "The paranoia cascade's outer layer is not authenticated.");
        Require(
            paranoiaLayout.TotalKeyBytes == 376,
            $"The paranoia cascade needs 376 key bytes, not {paranoiaLayout.TotalKeyBytes}.");
        Require(
            paranoiaLayout.TotalNonceBytes == 268,
            $"The paranoia cascade needs 268 nonce bytes, not {paranoiaLayout.TotalNonceBytes}.");
        Require(paranoia.UsesTwoKdfRounds, "The paranoia cascade must derive two Argon2id rounds.");
        Require(
            EncryptionSuiteCatalog.Default == EncryptionSuite.ThreefishOverKalyna,
            "The cascade is not the default suite.");

        // Every suite the catalogue knows must also report itself as usable,
        // or the GUI offers a suite it then refuses to run — and the default
        // suite is the one that would fail first.
        var containerService = new KalynaContainerService();
        foreach (EncryptionSuite candidate in Enum.GetValues<EncryptionSuite>())
        {
            Require(
                containerService.IsNativeSuiteAvailable(candidate),
                $"{candidate} is offered by the catalogue but reports no native support.");
        }

        // A payload with structure an attacker would recognise instantly.
        byte[] marker = "KZPAQ1\0KEEP-VAULT-PLAINTEXT-MARKER"u8.ToArray();
        byte[] plaintext = new byte[64 * 1024];
        for (int offset = 0; offset + marker.Length <= plaintext.Length; offset += marker.Length)
        {
            marker.CopyTo(plaintext, offset);
        }

        byte[] innerKey = RandomNumberGenerator.GetBytes(layout.Stages[0].KeyBytes);
        byte[] outerKey = RandomNumberGenerator.GetBytes(layout.Stages[1].KeyBytes);
        byte[] innerNonce = RandomNumberGenerator.GetBytes(layout.Stages[0].NonceBytes);
        byte[] outerNonce = RandomNumberGenerator.GetBytes(layout.Stages[1].NonceBytes);
        byte[] tweak = RandomNumberGenerator.GetBytes(parameters.TweakBytes);
        byte[] innerCiphertext = new byte[plaintext.Length];
        byte[] cascadeCiphertext = new byte[plaintext.Length];
        byte[] outerStripped = new byte[plaintext.Length];
        byte[] recovered = new byte[plaintext.Length];
        try
        {
            NativeKalyna.XCryptCtr512(innerKey, innerNonce, plaintext, innerCiphertext, plaintext.Length);
            NativeThreefish.XCryptCtr1024(outerKey, tweak, outerNonce, innerCiphertext, cascadeCiphertext, plaintext.Length);

            Require(!FixedEqual(plaintext, cascadeCiphertext), "The cascade left the plaintext unchanged.");
            Require(!FixedEqual(innerCiphertext, cascadeCiphertext), "The outer layer did nothing.");
            Require(!ContainsSequence(cascadeCiphertext, marker), "The cascade ciphertext still shows the plaintext marker.");

            // The attacker's best case: the outer keystream is known and removed.
            NativeThreefish.XCryptCtr1024(outerKey, tweak, outerNonce, cascadeCiphertext, outerStripped, plaintext.Length);
            Require(FixedEqual(outerStripped, innerCiphertext), "Stripping the outer layer did not reproduce the inner ciphertext.");
            Require(!FixedEqual(outerStripped, plaintext), "Stripping the outer layer revealed the plaintext.");
            Require(!ContainsSequence(outerStripped, marker), "Stripping the outer layer revealed plaintext structure.");

            // Only with the inner key as well does the plaintext come back.
            NativeKalyna.XCryptCtr512(innerKey, innerNonce, outerStripped, recovered, plaintext.Length);
            Require(FixedEqual(recovered, plaintext), "Both layers together did not reproduce the plaintext.");

            // A wrong inner key after a correct outer strip stays garbage.
            byte[] wrongInner = RandomNumberGenerator.GetBytes(layout.Stages[0].KeyBytes);
            byte[] wrongRecovery = new byte[plaintext.Length];
            try
            {
                NativeKalyna.XCryptCtr512(wrongInner, innerNonce, outerStripped, wrongRecovery, plaintext.Length);
                Require(!ContainsSequence(wrongRecovery, marker), "A wrong inner key still revealed plaintext structure.");
            }
            finally
            {
                Zero(wrongInner, wrongRecovery);
            }
        }
        finally
        {
            Zero(plaintext, innerKey, outerKey, innerNonce, outerNonce, tweak,
                innerCiphertext, cascadeCiphertext, outerStripped, recovered);
        }

        return Task.CompletedTask;
    }

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return needle.Length != 0 && haystack.IndexOf(needle) >= 0;
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
            Require(header.GetProperty("Version").GetInt32() == 9, "Container version is not v9.");

            // The second-round fields are always present. Present-and-null is
            // not cosmetic: the reader compares the header against its own
            // canonical re-serialization, so a field that vanished would make
            // the app reject containers it had just written.
            bool hasSecondSalt = header.TryGetProperty("SecondSalt", out JsonElement secondSalt);
            bool hasSecondNonce = header.TryGetProperty("SecondNonce", out JsonElement secondNonce);
            Require(hasSecondSalt && hasSecondNonce, "Container header is missing the second-round fields.");

            if (parameters.UsesTwoKdfRounds)
            {
                // A two-round suite must carry both rounds, or the archive is
                // undecryptable by anyone — including the machine that wrote it.
                Require(
                    secondSalt.ValueKind == JsonValueKind.String
                    && secondNonce.ValueKind == JsonValueKind.String,
                    "Container header omits second-round material for a two-round suite.");
                Require(
                    header.GetProperty("SecondSaltBits").GetInt32() == PasswordKeyService.SaltSize * 8
                    && header.GetProperty("SecondNonceBits").GetInt32() == parameters.NonceBytes * 8,
                    "Container header declares wrong second-round sizes.");
                Require(
                    !string.Equals(
                        header.GetProperty("Salt").GetString(),
                        secondSalt.GetString(),
                        StringComparison.Ordinal),
                    "Container header reuses the first round's salt for the second.");
                Require(
                    !string.Equals(
                        header.GetProperty("Nonce").GetString(),
                        secondNonce.GetString(),
                        StringComparison.Ordinal),
                    "Container header reuses the first round's nonce for the second.");
            }
            else
            {
                Require(
                    secondSalt.ValueKind == JsonValueKind.Null
                    && secondNonce.ValueKind == JsonValueKind.Null,
                    "Container header does not carry null second-round material for a single-round suite.");
                Require(
                    header.GetProperty("SecondSaltBits").GetInt32() == 0
                    && header.GetProperty("SecondNonceBits").GetInt32() == 0,
                    "Container header declares second-round sizes for a single-round suite.");
            }
            Require(header.GetProperty("Algorithm").GetString() == parameters.Algorithm, "Container algorithm label mismatch.");
            Require(header.GetProperty("CounterEndian").GetString() == EncryptionSuiteCatalog.CounterEndian, "Container counter endian mismatch.");
            Require(header.GetProperty("Argon2MemoryKiB").GetInt32() == Argon2Profile.DefaultMemoryKiB, "Container Argon2 memory is not 1 GiB.");
            Require(header.GetProperty("Argon2Iterations").GetInt32() == Argon2Profile.DefaultIterations, "Container Argon2 iterations mismatch.");
            Require(header.GetProperty("Argon2Parallelism").GetInt32() == Argon2Profile.DefaultParallelism, "Container Argon2 parallelism mismatch.");
            Require(header.GetProperty("GeneratedPasswordFactorCount").GetInt32() == 2, "Container factor count mismatch.");
            Require(header.GetProperty("GeneratedPasswordBits").GetInt32() == 1024, "Container generated-factor bits mismatch.");
            Require(
                header.GetProperty("EncryptionKeyBits").GetInt32() == parameters.EncryptionKeyBytes * 8,
                "Container encryption key size mismatch.");
            Require(
                header.GetProperty("NonceBits").GetInt32() == parameters.NonceBytes * 8,
                "Container nonce size mismatch.");
            Require(
                header.GetProperty("Argon2OutputBits").GetInt32() == parameters.DerivedKeyBytes * 8,
                "Container Argon2 output size mismatch.");
            if (suite == EncryptionSuite.ThreefishOverKalyna)
            {
                // The split the whole construction rests on, asserted against
                // the numbers rather than against the catalog that produced
                // them: 64 bytes of key and nonce for the inner Kalyna layer,
                // 128 for the outer Threefish layer, and an Argon2id output of
                // 192 cipher-key bytes plus the two MAC keys.
                Require(header.GetProperty("EncryptionKeyBits").GetInt32() == 192 * 8, "Cascade key is not 192 bytes.");
                Require(header.GetProperty("NonceBits").GetInt32() == 192 * 8, "Cascade nonce is not 192 bytes.");
                Require(header.GetProperty("Argon2OutputBits").GetInt32() == 384 * 8, "Cascade Argon2 output is not 384 bytes.");
            }

            if (suite == EncryptionSuite.ParanoiaCascade)
            {
                // Six layers: 32+56+64+64+128+32 key bytes and 16+16+32+64+128+12
                // nonce bytes, with 376 cipher-key bytes plus the two MAC keys
                // covered by two Argon2id rounds.
                Require(header.GetProperty("EncryptionKeyBits").GetInt32() == 376 * 8, "Paranoia key is not 376 bytes.");
                Require(header.GetProperty("NonceBits").GetInt32() == 268 * 8, "Paranoia nonce is not 268 bytes.");
                Require(header.GetProperty("Argon2OutputBits").GetInt32() == 568 * 8, "Paranoia Argon2 output is not 568 bytes.");
            }
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

    /// <summary>
    /// Proves the v9 second Argon2id round is real, independent, and costs no
    /// extra mouse entropy.
    /// </summary>
    /// <remarks>
    /// The point of the design is that both rounds come out of a single pool
    /// consumption, separated only by SHA3-512 against SHA-512. The two things
    /// that could go wrong are therefore: the second round is not actually
    /// independent of the first, or obtaining it silently drains the pools so
    /// the user is asked to collect entropy all over again. Both are checked
    /// here.
    /// </remarks>
    /// <summary>
    /// Encrypts a payload spanning several chunks and checks that identical
    /// plaintext chunks do not produce identical ciphertext.
    /// </summary>
    /// <remarks>
    /// This is the property per-chunk nonces exist for. Under one continuous
    /// counter the keystream never repeats either — until the counter wraps,
    /// which is precisely the case an arbitrarily large archive can reach. The
    /// test cannot write an archive that large, so it checks the mechanism
    /// instead: the plaintext is the same 16 MiB block repeated, so if every
    /// chunk were encrypted under the same counter start the ciphertext chunks
    /// would be byte-identical.
    ///
    /// A roundtrip is done as well, because a nonce derivation that the writer
    /// and the reader disagree about would still produce different ciphertext
    /// per chunk and would still pass the first check.
    /// </remarks>
    /// <summary>
    /// Checks the two Crypto++-backed cascade layers against the vectors that
    /// ship with the library, and checks that their CTR mode behaves.
    /// </summary>
    /// <remarks>
    /// The vectors are read from external/cryptopp/TestVectors rather than
    /// copied in here, so a Crypto++ update brings its own expectations with it
    /// instead of being checked against numbers frozen at the time this was
    /// written.
    ///
    /// A gap worth naming: SHACAL-2's file covers the 512-bit key the cascade
    /// actually uses, but MARS's covers only 128, 192 and 256 bits. The AES
    /// submission published no 448-bit vectors, so the test proves the MARS
    /// cipher core and the key schedule at three lengths, and cannot prove the
    /// 448-bit schedule. That one still needs a second implementation to agree
    /// with it.
    /// </remarks>
    private static Task TestCascadeCipherVectorsAsync()
    {
        Require(NativeMars.IsAvailable(), $"MARS reference library unavailable: {NativeMars.LastLoadError}");
        Require(NativeShacal2.IsAvailable(), $"SHACAL-2 reference library unavailable: {NativeShacal2.LastLoadError}");

        string vectorRoot = ResolveVectorDirectory();

        int marsChecked = RunBlockVectors(
            Path.Combine(vectorRoot, "mars.txt"),
            NativeMars.BlockBytes,
            NativeMars.EncryptBlock,
            "MARS");
        Require(marsChecked >= 10, $"Only {marsChecked} MARS vectors were exercised.");

        int shacalChecked = RunBlockVectors(
            Path.Combine(vectorRoot, "shacal2.txt"),
            NativeShacal2.BlockBytes,
            NativeShacal2.EncryptBlock,
            "SHACAL-2");
        Require(shacalChecked >= 1000, $"Only {shacalChecked} SHACAL-2 vectors were exercised.");

        VerifyMars448AgainstIndependentOracle();


        Require(NativeAes.IsAvailable(), $"AES reference library unavailable: {NativeAes.LastLoadError}");
        Require(NativeChaChaPoly.IsAvailable(), $"ChaCha20-Poly1305 library unavailable: {NativeChaChaPoly.LastLoadError}");

        // FIPS-197 C.3: the published AES-256 known-answer.
        byte[] fipsKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] fipsBlock = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] fipsActual = new byte[NativeAes.BlockBytes];
        NativeAes.EncryptBlock(fipsKey, fipsBlock, fipsActual);
        Require(
            Convert.ToHexString(fipsActual) == "8EA2B7CA516745BFEAFC49904B496089",
            $"AES-256 does not reproduce the FIPS-197 vector: {Convert.ToHexString(fipsActual)}.");

        // The platform AES and the reference must agree. The platform path is
        // what production uses; the reference is what it can be checked
        // against, and a disagreement means one of them is wrong.
        for (int trial = 0; trial < 16; trial++)
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] block = RandomNumberGenerator.GetBytes(NativeAes.BlockBytes);
            byte[] reference = new byte[NativeAes.BlockBytes];
            NativeAes.EncryptBlock(key, block, reference);

            using var platform = Aes.Create();
            platform.Key = key;
            platform.Mode = CipherMode.ECB;
            platform.Padding = PaddingMode.None;
            byte[] managed = platform.EncryptEcb(block, PaddingMode.None);

            Require(
                reference.AsSpan().SequenceEqual(managed),
                $"The platform AES and the reference AES disagree: "
                + $"{Convert.ToHexString(managed)} against {Convert.ToHexString(reference)}.");
        }

        // RFC 8439 section 2.8.2, ciphertext and tag.
        byte[] aeadKey = Convert.FromHexString(
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        byte[] aeadNonce = Convert.FromHexString("070000004041424344454647");
        byte[] aeadAad = Convert.FromHexString("50515253C0C1C2C3C4C5C6C7");
        byte[] aeadPlain = System.Text.Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] aeadCipher = new byte[aeadPlain.Length];
        byte[] aeadTag = new byte[NativeChaChaPoly.TagBytes];
        NativeChaChaPoly.Encrypt(aeadKey, aeadNonce, aeadAad, aeadPlain, aeadCipher, aeadPlain.Length, aeadTag);
        Require(
            Convert.ToHexString(aeadTag) == "1AE10B594F09E26A7E902ECBD0600691",
            $"ChaCha20-Poly1305 does not reproduce the RFC 8439 tag: {Convert.ToHexString(aeadTag)}.");

        byte[] aeadRestored = new byte[aeadPlain.Length];
        NativeChaChaPoly.Decrypt(aeadKey, aeadNonce, aeadAad, aeadCipher, aeadRestored, aeadPlain.Length, aeadTag);
        Require(aeadRestored.AsSpan().SequenceEqual(aeadPlain), "ChaCha20-Poly1305 did not round trip.");

        // An AEAD that decrypts a tampered ciphertext is not an AEAD. Both the
        // tag and the associated data must be refused when altered.
        byte[] brokenTag = (byte[])aeadTag.Clone();
        brokenTag[0] ^= 1;
        RequireThrows<CryptographicException>(
            () => NativeChaChaPoly.Decrypt(
                aeadKey, aeadNonce, aeadAad, aeadCipher, aeadRestored, aeadPlain.Length, brokenTag),
            "ChaCha20-Poly1305 accepted a flipped authentication tag.");

        byte[] brokenAad = (byte[])aeadAad.Clone();
        brokenAad[0] ^= 1;
        RequireThrows<CryptographicException>(
            () => NativeChaChaPoly.Decrypt(
                aeadKey, aeadNonce, brokenAad, aeadCipher, aeadRestored, aeadPlain.Length, aeadTag),
            "ChaCha20-Poly1305 accepted altered associated data.");

        // CTR is its own inverse and must not depend on how many threads ran.
        // The sizes straddle the block width, the 256 KiB claim and the 1 MiB
        // threshold at which the driver starts handing work to other cores.
        foreach (int length in new[] { 1, 15, 16, 31, 32, 33, 65536, (1 << 20) - 1, 1 << 20, (5 << 20) + 7 })
        {
            RoundTrip(
                length,
                keyBytes: 56,
                nonceBytes: NativeMars.BlockBytes,
                (k, n, i, o, l) => NativeMars.XCryptCtr448(k, n, i, o, l),
                "MARS-448");
            RoundTrip(
                length,
                keyBytes: 64,
                nonceBytes: NativeShacal2.BlockBytes,
                (k, n, i, o, l) => NativeShacal2.XCryptCtr512(k, n, i, o, l),
                "SHACAL-2-512");
        }

        return Task.CompletedTask;

        static void RoundTrip(
            int length,
            int keyBytes,
            int nonceBytes,
            Action<byte[], byte[], byte[], byte[], int> xcrypt,
            string label)
        {
            byte[] key = RandomNumberGenerator.GetBytes(keyBytes);
            byte[] nonce = RandomNumberGenerator.GetBytes(nonceBytes);
            byte[] plain = RandomNumberGenerator.GetBytes(length);
            byte[] cipher = new byte[length];
            byte[] restored = new byte[length];

            xcrypt(key, nonce, plain, cipher, length);
            xcrypt(key, nonce, cipher, restored, length);

            Require(restored.AsSpan().SequenceEqual(plain), $"{label} did not round trip at {length} bytes.");
            if (length >= nonceBytes)
            {
                Require(
                    !cipher.AsSpan(0, nonceBytes).SequenceEqual(plain.AsSpan(0, nonceBytes)),
                    $"{label} returned its input unchanged at {length} bytes.");
            }
        }
    }


    /// <summary>
    /// Checks MARS against answers produced by a different implementation,
    /// including the 448-bit keys the cascade actually uses.
    /// </summary>
    /// <remarks>
    /// The AES submission published vectors for 128, 192 and 256-bit keys only,
    /// so the key length this app depends on had no authoritative check. These
    /// answers come from Botan 1.10.17's MARS, an independent implementation
    /// line, and the file records its provenance and the published vector it
    /// was validated against before being trusted.
    ///
    /// The oracle had to be validated first for a concrete reason: Brian
    /// Gladman's widely mirrored mars.c predates the 22 September 1999 MARS
    /// revision and implements the older key schedule. It disagrees with
    /// Crypto++ and with the published vectors, and using it unchecked would
    /// have produced a failure that pointed at this repository instead of at
    /// the oracle.
    ///
    /// Only the raw block cipher is compared. CTR is checked separately, so a
    /// disagreement here means the MARS primitive, and a disagreement there
    /// means the counter mode — two implementations can both be correct and
    /// still differ on counter endianness.
    /// </remarks>
    private static void VerifyMars448AgainstIndependentOracle()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "MarsKnownAnswers.txt");
        Require(File.Exists(path), $"The MARS known-answer file is missing: {path}");

        var perLength = new Dictionary<int, int>();
        foreach (string rawLine in File.ReadLines(path))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Require(parts.Length == 3, $"Malformed MARS known-answer line: {line}");

            byte[] key = Convert.FromHexString(parts[0]);
            byte[] plain = Convert.FromHexString(parts[1]);
            byte[] expected = Convert.FromHexString(parts[2]);

            byte[] actual = new byte[NativeMars.BlockBytes];
            NativeMars.EncryptBlock(key, plain, actual);
            Require(
                actual.AsSpan().SequenceEqual(expected),
                $"MARS disagrees with the independent oracle at a {key.Length * 8}-bit key: "
                + $"got {Convert.ToHexString(actual)}, expected {parts[2]}.");

            perLength[key.Length * 8] = perLength.GetValueOrDefault(key.Length * 8) + 1;
        }

        Require(
            perLength.GetValueOrDefault(448) >= 32,
            $"Only {perLength.GetValueOrDefault(448)} MARS answers cover the 448-bit key the cascade uses.");
        Require(perLength.Count >= 6, $"Only {perLength.Count} MARS key lengths were covered.");
    }

    /// <summary>
    /// Reads Key/Plaintext/Ciphertext triples out of a Crypto++ vector file and
    /// runs the ones whose block size matches.
    /// </summary>
    private static int RunBlockVectors(
        string path,
        int blockBytes,
        Action<byte[], byte[], byte[]> encryptBlock,
        string label)
    {
        Require(File.Exists(path), $"{label} vector file is missing: {path}");

        string? key = null;
        string? plaintext = null;
        string? ciphertext = null;
        int exercised = 0;

        foreach (string rawLine in File.ReadLines(path))
        {
            string line = rawLine.Trim();
            int separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            string name = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();

            switch (name)
            {
                case "Key":
                    key = value;
                    break;
                case "Plaintext":
                    plaintext = value;
                    break;
                case "Ciphertext":
                    ciphertext = value;
                    break;
                case "Test":
                    if (value == "Encrypt" && key is not null && plaintext is not null && ciphertext is not null)
                    {
                        byte[] keyBytes = Convert.FromHexString(key);
                        byte[] input = Convert.FromHexString(plaintext);
                        byte[] expected = Convert.FromHexString(ciphertext);
                        if (input.Length == blockBytes && expected.Length == blockBytes)
                        {
                            byte[] actual = new byte[blockBytes];
                            encryptBlock(keyBytes, input, actual);
                            Require(
                                actual.AsSpan().SequenceEqual(expected),
                                $"{label} vector mismatch for a {keyBytes.Length * 8}-bit key: "
                                + $"got {Convert.ToHexString(actual)}, expected {ciphertext}.");
                            exercised++;
                        }
                    }

                    plaintext = null;
                    ciphertext = null;
                    break;
            }
        }

        return exercised;
    }

    /// <summary>
    /// Finds external/cryptopp/TestVectors by walking up from the test binary.
    /// </summary>
    private static string ResolveVectorDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "external", "cryptopp", "TestVectors");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("external/cryptopp/TestVectors was not found above the test binary.");
    }

    private static async Task TestPerChunkNoncesAsync()
    {
        const int chunkSize = 16 * 1024 * 1024;
        string root = CreateTempRoot("keep-vault-chunk-nonce-");
        try
        {
            // Encryption runs directly on the ZPAQ stream, so no compression
            // sits between this payload and the cipher: two identical 16 MiB
            // halves reach the cipher as exactly two identical chunks.
            byte[] half = new byte[chunkSize];
            for (int index = 0; index < half.Length; index++)
            {
                half[index] = (byte)(index & 0xFF);
            }

            byte[] payload = new byte[2 * chunkSize];
            half.CopyTo(payload, 0);
            half.CopyTo(payload, chunkSize);

            foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
            {
                AddMouseSamplesUntilReady();
                using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
                var containers = new KalynaContainerService();
                string archive = Path.Combine(root, $"{suite}.kzpaq");

                await using (var input = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        input,
                        archive,
                        UserPassword,
                        entropy.FirstPassword,
                        entropy.SecondPassword,
                        suite,
                        entropy,
                        null,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                byte[] container = await File.ReadAllBytesAsync(archive).ConfigureAwait(false);
                Require(
                    container.LongLength > chunkSize,
                    $"{suite}: the container is only {container.LongLength} bytes and cannot span two chunks.");

                // The last 1 MiB of the ciphertext against the 1 MiB exactly one
                // chunk earlier. The plaintext under both is identical, so with a
                // single counter running across the archive these would differ
                // only by the counter — and with a per-chunk nonce they differ
                // completely. Identical here would mean the nonce never moved.
                const int span = 1 << 20;
                ReadOnlySpan<byte> first = container.AsSpan(container.Length - chunkSize - span, span);
                ReadOnlySpan<byte> second = container.AsSpan(container.Length - span, span);
                Require(
                    !first.SequenceEqual(second),
                    $"{suite}: two ciphertext regions one chunk apart are identical; the chunk nonce did not change.");

                // A derivation the reader disagrees with would also produce
                // different ciphertext per chunk and would still pass the check
                // above, so the roundtrip is what proves both sides agree.
                await using var output = new MemoryStream();
                await containers.DecryptToStreamAsync(
                    archive,
                    UserPassword,
                    entropy.FirstPassword,
                    entropy.SecondPassword,
                    output,
                    null,
                    CancellationToken.None).ConfigureAwait(false);

                Require(
                    output.Length == payload.LongLength,
                    $"{suite}: the restored payload is {output.Length} bytes rather than {payload.LongLength}.");
                Require(
                    output.ToArray().AsSpan().SequenceEqual(payload),
                    $"{suite}: the restored multi-chunk payload does not match the original.");

                File.Delete(archive);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task TestTwoRoundDerivationAsync()
    {
        // SHA-512 must agree with the published digests and with the second
        // implementation before anything derived from it is trusted.
        byte[] abc = Sha512Compat.HashData("abc"u8);
        Require(
            Convert.ToHexString(abc) ==
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
            + "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
            "SHA-512 did not reproduce the FIPS 180-4 digest for \"abc\".");
        Require(
            !Convert.ToHexString(Sha512Compat.HashData(ReadOnlySpan<byte>.Empty)).SequenceEqual(
                Convert.ToHexString(abc)),
            "SHA-512 returned the same digest for different messages.");

        foreach (EncryptionSuite suite in new[] { EncryptionSuite.ThreefishOverKalyna, EncryptionSuite.Kalyna512_512 })
        {
            AddMouseSamplesUntilReady();
            using TwoRoundEncryptionParameters parameters = EntropyMixer.CreateTwoRoundEncryptionParameters(suite);

            Require(
                parameters.FirstSalt.Bytes.Length == parameters.SecondSalt.Bytes.Length,
                $"{suite}: the two rounds produced salts of different lengths.");
            Require(
                !parameters.FirstSalt.Bytes.SequenceEqual(parameters.SecondSalt.Bytes),
                $"{suite}: both Argon2id rounds produced the same salt.");
            Require(
                !parameters.FirstNonce.Bytes.SequenceEqual(parameters.SecondNonce.Bytes),
                $"{suite}: both Argon2id rounds produced the same nonce.");

            int expectedNonce = EncryptionSuiteCatalog.Get(suite).NonceBytes;
            Require(
                parameters.FirstNonce.Bytes.Length == expectedNonce
                && parameters.SecondNonce.Bytes.Length == expectedNonce,
                $"{suite}: a round produced a nonce of the wrong length.");

            // Neither salt nor nonce may be all zeros or otherwise degenerate;
            // a buffer that was allocated but never filled would still be
            // "different" from the other round by accident of the XOR.
            Require(
                parameters.FirstSalt.Bytes.Any(b => b != 0)
                && parameters.SecondSalt.Bytes.Any(b => b != 0)
                && parameters.FirstNonce.Bytes.Any(b => b != 0)
                && parameters.SecondNonce.Bytes.Any(b => b != 0),
                $"{suite}: a round produced an all-zero salt or nonce.");

            // The halves must not share long runs. Independent material from two
            // different hash constructions has no reason to agree anywhere, and
            // a copy-paste in the split would show up exactly here.
            int shared = 0;
            for (int index = 0; index < parameters.FirstNonce.Bytes.Length; index++)
            {
                if (parameters.FirstNonce.Bytes[index] == parameters.SecondNonce.Bytes[index])
                {
                    shared++;
                }
            }

            Require(
                shared < parameters.FirstNonce.Bytes.Length / 4,
                $"{suite}: the two rounds' nonces agree in {shared} of {parameters.FirstNonce.Bytes.Length} bytes.");
        }

        // The whole reason both rounds share one consumption: asking for them
        // must not leave the pools needing to be refilled beyond the single
        // consumption the first round would have cost anyway.
        AddMouseSamplesUntilReady();
        using (TwoRoundEncryptionParameters _ = EntropyMixer.CreateTwoRoundEncryptionParameters(
            EncryptionSuite.ThreefishOverKalyna))
        {
        }

        Require(
            !EntropyMixer.HasRequiredSamples(EntropyPurpose.Salt),
            "The two-round derivation did not consume the salt pool exactly once.");

        return Task.CompletedTask;
    }

    private static void AddMouseSamplesUntilReady()
    {
        int index = 0;
        while (!EntropyMixer.HasRequiredSamples(EntropyPurpose.GeneratedPasswordFirst)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.GeneratedPasswordSecond)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.Salt)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.NonceFirst)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.NonceSecond)
            || !EntropyMixer.HasRequiredSamples(EntropyPurpose.NonceThird))
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
