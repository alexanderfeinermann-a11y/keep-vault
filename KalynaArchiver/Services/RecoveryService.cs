using System.Buffers.Binary;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

public enum RecoveryProtectionMode
{
    ErrorCorrectionOnly = 0,
    DualAuthenticatedEncrypted = 1,
}

public sealed partial class RecoveryService
{
    private static readonly byte[] LocatorMagic = "KPR2LOC2"u8.ToArray();
    private static readonly byte[] MetadataBlockMagic = "KPR2BLK2"u8.ToArray();
    private static readonly byte[] MetadataEnvelopeMagic = "KPR2META"u8.ToArray();
    private static readonly byte[] CertificationDomain = "Kalyna-ZPAQ/KPAR2/v3/Metadata-Certification"u8.ToArray();
    private static readonly byte[] Sha3KeyDomain = "Kalyna-ZPAQ/KPAR2/v3/SHA3-Recovery-Key"u8.ToArray();
    private static readonly byte[] SkeinKeyDomain = "Kalyna-ZPAQ/KPAR2/v3/Skein-Recovery-Key"u8.ToArray();

    /// <summary>
    /// KPAR2 format version. 3 is the container v10 layout: the salt field is
    /// a 1024-bit pair rather than a single 512-bit salt, and the Argon2id cost
    /// fields are gone because v10 derives the memory cost from the credentials
    /// and must not publish it.
    /// </summary>
    private const int Version = 3;

    /// <summary>
    /// One v10 salt pair: the SHA3 branch's salt followed by the Skein
    /// branch's.
    /// </summary>
    private const int SaltPairBytes = 128;

    /// <summary>
    /// The most salt an encrypted locator can carry: one pair per KDF round,
    /// and the two-round suite uses two.
    /// </summary>
    private const int LocatorSaltBytes = 2 * SaltPairBytes;

    /// <summary>
    /// Everything in the canonical locator context except the salt: five
    /// 32-bit fields, four 64-bit fields, three more 32-bit fields and the
    /// 32-byte archive identifier.
    /// </summary>
    private const int LocatorCertificationContextFixedBytes = (5 * 4) + (3 * 8) + 4 + 8 + 4 + 4 + 32;

    /// <summary>
    /// How many salt bytes a suite's KPAR2 bootstrap needs.
    /// </summary>
    /// <remarks>
    /// Read from the catalogue rather than fixed, so a suite added later gets
    /// the right answer instead of whichever constant happened to be written
    /// down when this was first implemented.
    /// </remarks>
    private static int ExpectedLocatorSaltBytes(int encryptionSuite) =>
        !IsKnownLocatorSuite(encryptionSuite)
            ? 0
            : EncryptionSuiteCatalog.Get((EncryptionSuite)encryptionSuite).UsesTwoKdfRounds
                ? 2 * SaltPairBytes
                : SaltPairBytes;
    private const string RecoveryAlgorithm = "KPAR2-v3-SHA3-512+Skein-1024-RS(20,3)";
    private const int DataShardCount = 20;
    private const int ParityShardCount = 3;
    private const int BodyShardSize = 4 * 1024 * 1024;
    private const int MinimumRecoveryShardSize = 4096;
    private const int RecoveryBlockAlignment = 4096;
    private const int PlainHeaderBytes = 64 * 1024;
    private const long MaxArchiveBytes = 1L << 40;

    private const int LocatorBlockSize = 4096;
    private const int LocatorAuthenticatedBytes = 3904;
    private const int LocatorSkeinOffset = 3904;
    private const int LocatorSha3Offset = 4032;
    private const int PrefixLocatorCopies = 4;
    private const int SuffixLocatorCopies = 4;
    private const int PrefixLocatorBytes = PrefixLocatorCopies * LocatorBlockSize;
    private const int SuffixLocatorBytes = SuffixLocatorCopies * LocatorBlockSize;
    private const int RequiredLocatorConsensus = 5;

    private const int MetadataBlockHeaderSize = 32;
    private const int MetadataPayloadSize = 3872;
    private const int MetadataBlockSkeinOffset = MetadataBlockHeaderSize + MetadataPayloadSize;
    private const int MetadataBlockSha3Offset = MetadataBlockSkeinOffset + Skein1024Digest.DigestSize;
    private const int MetadataEnvelopeHeaderSize = 8 + sizeof(int) + sizeof(int) + sizeof(long) + Sha3_512Compat.HashSizeInBytes + Skein1024Digest.DigestSize;
    private const int MaxMetadataEnvelopeBytes = 128 * 1024 * 1024;
    private const long MaxEncodedMetadataBytes = 192L * 1024 * 1024;
    private const int RecoverySidecarDestructionBytes = 1024 * 1024;
    private const int RecoveryCopyChunkBytes = 1024 * 1024;

    private readonly PasswordKeyService _passwords = new();
    private readonly KalynaContainerService _containers = new();
    private readonly ArchiveIntegrityService _archiveIntegrity = new();

    public static string GetRecoveryPath(string archivePath) => $"{archivePath}.kpar2";

    public static void DeleteRecoverySidecar(string archivePath)
    {
        string recoveryPath = GetRecoveryPath(archivePath);
        if (File.Exists(recoveryPath))
        {
            File.Delete(recoveryPath);
        }
    }

    // The beginning contains parity for the encrypted container header; the end contains
    // redundant bootstrap metadata. Both regions must be destroyed before deletion so a
    // deleted sidecar cannot trivially restore a cryptographically erased container header.
    public static void SecureDeleteRecoverySidecar(string archivePath)
    {
        SecureFile.DestroyPrefixAndSuffixAndDelete(
            GetRecoveryPath(archivePath),
            RecoverySidecarDestructionBytes,
            RecoverySidecarDestructionBytes);
    }

    public Task<string> CreateAsync(
        string archivePath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return CreateCoreAsync(
            archivePath,
            RecoveryProtectionMode.ErrorCorrectionOnly,
            null,
            null,
            null,
            null,
            progress,
            cancellationToken);
    }

    public Task<string> CreateAuthenticatedAsync(
        string archivePath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return CreateCoreAsync(
            archivePath,
            RecoveryProtectionMode.DualAuthenticatedEncrypted,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            progress,
            cancellationToken);
    }

    public Task<RecoveryRepairResult> VerifyAndRepairAsync(
        string archivePath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return RepairCoreAsync(
            archivePath,
            expectedMode: RecoveryProtectionMode.ErrorCorrectionOnly,
            authenticateMetadata: true,
            emergencyMode: false,
            null,
            null,
            null,
            null,
            progress,
            cancellationToken);
    }

    public Task<RecoveryRepairResult> VerifyAndRepairAuthenticatedAsync(
        string archivePath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return RepairCoreAsync(
            archivePath,
            expectedMode: RecoveryProtectionMode.DualAuthenticatedEncrypted,
            authenticateMetadata: true,
            emergencyMode: false,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            progress,
            cancellationToken);
    }

    public Task<RecoveryRepairResult> RecoverToNewFileAsync(
        string archivePath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return RepairCoreAsync(
            archivePath,
            expectedMode: RecoveryProtectionMode.ErrorCorrectionOnly,
            authenticateMetadata: false,
            emergencyMode: true,
            null,
            null,
            null,
            null,
            progress,
            cancellationToken);
    }

    public Task<RecoveryRepairResult> RecoverToNewFileAuthenticatedAsync(
        string archivePath,
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        return RepairCoreAsync(
            archivePath,
            expectedMode: RecoveryProtectionMode.DualAuthenticatedEncrypted,
            authenticateMetadata: false,
            emergencyMode: true,
            userPassword,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            progress,
            cancellationToken);
    }

    public async Task<RecoveryProtectionMode?> TryReadProtectionModeAsync(
        string archivePath,
        CancellationToken cancellationToken)
    {
        string recoveryPath = GetRecoveryPath(Path.GetFullPath(archivePath));
        if (!File.Exists(recoveryPath))
        {
            return null;
        }

#if KEEPVAULT_MACOS
        using MacPrivateFileSnapshot recoverySnapshot = await MacPrivateFileSnapshot
            .CaptureAsync(recoveryPath, cancellationToken)
            .ConfigureAwait(false);
        FileStream recovery = recoverySnapshot.Stream;
#else
        await using FileStream recovery = OpenRecoveryForRead(recoveryPath);
#endif
        RecoveryLocator locator = await ReadConsensusLocatorAsync(recovery, cancellationToken).ConfigureAwait(false);
        return locator.ProtectionMode;
    }

    private async Task<string> CreateCoreAsync(
        string archivePath,
        RecoveryProtectionMode protectionMode,
        string? userPassword,
        string? pin,
        string? firstGeneratedPassword,
        string? secondGeneratedPassword,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        string fullArchivePath = Path.GetFullPath(archivePath);
        string recoveryPath = GetRecoveryPath(fullArchivePath);
        string recoveryDirectory = Path.GetDirectoryName(recoveryPath) ?? Environment.CurrentDirectory;
        string temporaryPath = Path.Combine(
            recoveryDirectory,
            $".{Path.GetFileName(recoveryPath)}.{Guid.NewGuid():N}.recovery-part");
        bool recoveryInstalled = false;
        bool temporaryCreatedByThisOperation = false;
        byte[] archiveId = RandomNumberGenerator.GetBytes(32);
        ContainerRecoveryKdfInfo? kdfInfo = null;

        try
        {
#if KEEPVAULT_MACOS
            using MacPrivateFileSnapshot archiveSnapshot = await MacPrivateFileSnapshot
                .CaptureAsync(fullArchivePath, cancellationToken)
                .ConfigureAwait(false);
            FileStream archive = archiveSnapshot.Stream;
#else
            await using FileStream archive = new FileStream(
                fullArchivePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 1024 * 1024,
                FileOptions.RandomAccess);
#endif
            long archiveLength = archive.Length;
            if (archiveLength > MaxArchiveBytes)
            {
                throw new NotSupportedException($"Recovery supports archives up to {MaxArchiveBytes} bytes.");
            }

            bool hasEncryptedMagic = await HasEncryptedContainerMagicAsync(archive, cancellationToken).ConfigureAwait(false);
            if (protectionMode == RecoveryProtectionMode.ErrorCorrectionOnly)
            {
                if (hasEncryptedMagic
                    || string.Equals(
                        Path.GetExtension(fullArchivePath),
                        ".kzpaq",
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "Encrypted containers and .kzpaq targets require a dual-authenticated KPAR2 file. Use CreateAuthenticatedAsync.");
                }
            }
            else
            {
                if (userPassword is null || pin is null || firstGeneratedPassword is null || secondGeneratedPassword is null)
                {
                    throw new ArgumentException("All four credentials are required for authenticated recovery metadata.");
                }

                kdfInfo = await _containers.ReadRecoveryKdfInfoAsync(archive, cancellationToken).ConfigureAwait(false);
            }

            archive.Position = 0;
            (byte[] archiveSha3, byte[] archiveSkein) = await IntegrityService.HashStreamAsync(archive, cancellationToken).ConfigureAwait(false);
            try
            {
                long headerLength = AlignUp(
                    await DetectHeaderLengthAsync(archive, archiveLength, cancellationToken).ConfigureAwait(false),
                    RecoveryBlockAlignment);
                headerLength = Math.Clamp(headerLength, 0, archiveLength);

                var manifest = new RecoveryManifest
                {
                    Version = Version,
                    Algorithm = RecoveryAlgorithm,
                    ProtectionMode = protectionMode,
                    ArchiveFileName = Path.GetFileName(fullArchivePath),
                    ArchiveLength = archiveLength,
                    ArchiveSha3_512 = Convert.ToHexString(archiveSha3),
                    ArchiveSkein1024 = Convert.ToHexString(archiveSkein),
                    RedundancyPercent = 15,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    ArchiveId = Convert.ToBase64String(archiveId),
                    EncryptionAlgorithm = kdfInfo?.Algorithm,
                    EncryptionSuite = kdfInfo is null ? -1 : (int)kdfInfo.Suite,
                    Salt = kdfInfo is null ? null : Convert.ToBase64String(kdfInfo.Salt),
                    // Kept at zero in every mode. The fields are v2 leftovers
                    // and a v10 Argon2id cost is derived from the credentials;
                    // publishing it beside the salt would undo that.
                    Argon2MemoryKiB = 0,
                    Argon2Iterations = 0,
                    Argon2Parallelism = 0,
                };

                await using (var recovery = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1024 * 1024,
                    FileOptions.RandomAccess))
                {
                    temporaryCreatedByThisOperation = true;
                    await WriteZeroBytesAsync(recovery, PrefixLocatorBytes, cancellationToken).ConfigureAwait(false);

                    if (headerLength > 0)
                    {
                        manifest.Sections.Add(await CreateSectionAsync(
                            archive,
                            recovery,
                            "Header",
                            offset: 0,
                            length: headerLength,
                            shardSize: ChooseHeaderShardSize(headerLength),
                            progress,
                            cancellationToken).ConfigureAwait(false));
                    }

                    if (archiveLength > headerLength)
                    {
                        manifest.Sections.Add(await CreateSectionAsync(
                            archive,
                            recovery,
                            "Archive",
                            offset: headerLength,
                            length: archiveLength - headerLength,
                            shardSize: ChooseBodyShardSize(archiveLength - headerLength),
                            progress,
                            cancellationToken).ConfigureAwait(false));
                    }

                    long metadataOffset = recovery.Position;
                    if (metadataOffset % RecoveryBlockAlignment != 0)
                    {
                        throw new InvalidDataException("Internal KPAR2 parity layout is not 4096-byte aligned.");
                    }

                    byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, RecoveryJsonContext.Default.RecoveryManifest);
                    byte[]? envelope = null;
                    byte[]? envelopeSha3 = null;
                    byte[]? envelopeSkein = null;
                    byte[]? locatorBlock = null;
                    RecoveryKeys? recoveryKeys = null;
                    try
                    {
                        int envelopeLength = checked(MetadataEnvelopeHeaderSize + manifestBytes.Length);
                        if (envelopeLength > MaxMetadataEnvelopeBytes)
                        {
                            throw new InvalidDataException("Recovery metadata exceeds the supported size.");
                        }

                        int metadataStripeCount = checked((int)DivideRoundUp(
                            envelopeLength,
                            (long)DataShardCount * MetadataPayloadSize));
                        long metadataEncodedLength = checked(
                            (long)metadataStripeCount
                            * (DataShardCount + ParityShardCount)
                            * LocatorBlockSize);
                        if (metadataEncodedLength > MaxEncodedMetadataBytes)
                        {
                            throw new InvalidDataException("Encoded recovery metadata exceeds the supported size.");
                        }

                        var locator = new RecoveryLocator(
                            protectionMode,
                            metadataOffset,
                            metadataEncodedLength,
                            envelopeLength,
                            metadataStripeCount,
                            archiveLength,
                            kdfInfo is null ? -1 : (int)kdfInfo.Suite,
                            (byte[])archiveId.Clone(),
                            kdfInfo?.Salt.ToArray() ?? [],
                            new byte[Sha3_512Compat.HashSizeInBytes],
                            new byte[Skein1024Digest.DigestSize]);

                        if (protectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
                        {
                            recoveryKeys = await DeriveRecoveryKeysAsync(
                                userPassword!,
                                pin!,
                                firstGeneratedPassword!,
                                secondGeneratedPassword!,
                                locator,
                                cancellationToken).ConfigureAwait(false);
                        }

                        (byte[] certificationSha3, byte[] certificationSkein) =
                            ComputeMetadataCertification(locator, manifestBytes, recoveryKeys);
                        try
                        {
                            envelope = BuildMetadataEnvelope(
                                protectionMode,
                                manifestBytes,
                                certificationSha3,
                                certificationSkein);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(certificationSha3);
                            CryptographicOperations.ZeroMemory(certificationSkein);
                        }

                        (envelopeSha3, envelopeSkein) = ComputeDualHash(envelope);
                        locator = locator with
                        {
                            EnvelopeSha3 = envelopeSha3.ToArray(),
                            EnvelopeSkein = envelopeSkein.ToArray(),
                        };
                        locatorBlock = BuildLocatorBlock(locator);

                        await WriteEncodedMetadataAsync(recovery, envelope, locator, cancellationToken).ConfigureAwait(false);
                        for (int i = 0; i < SuffixLocatorCopies; i++)
                        {
                            await recovery.WriteAsync(locatorBlock, cancellationToken).ConfigureAwait(false);
                        }

                        recovery.Position = 0;
                        for (int i = 0; i < PrefixLocatorCopies; i++)
                        {
                            await recovery.WriteAsync(locatorBlock, cancellationToken).ConfigureAwait(false);
                        }

                        long expectedLength = checked(
                            metadataOffset + metadataEncodedLength + SuffixLocatorBytes);
                        if (recovery.Length != expectedLength)
                        {
                            throw new InvalidDataException("Internal KPAR2 layout length mismatch.");
                        }

                        await recovery.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) makes the complete recovery file durable before installation.
                        recovery.Flush(flushToDisk: true);
#pragma warning restore CA1849
                    }
                    finally
                    {
                        recoveryKeys?.Dispose();
                        CryptographicOperations.ZeroMemory(manifestBytes);
                        ZeroIfNotNull(envelope);
                        ZeroIfNotNull(envelopeSha3);
                        ZeroIfNotNull(envelopeSkein);
                        ZeroIfNotNull(locatorBlock);
                    }
                }

                SecureDeleteRecoverySidecar(fullArchivePath);
                File.Move(temporaryPath, recoveryPath, overwrite: false);
                recoveryInstalled = true;
                progress?.Report(
                    protectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                        ? $"Dual-authenticated KPAR2 file written: {recoveryPath}"
                        : $"KPAR2 error-correction file written (not authenticated): {recoveryPath}");
                return recoveryPath;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(archiveSha3);
                CryptographicOperations.ZeroMemory(archiveSkein);
            }
        }
        finally
        {
            kdfInfo?.Dispose();
            CryptographicOperations.ZeroMemory(archiveId);
            if (temporaryCreatedByThisOperation
                && !recoveryInstalled
                && File.Exists(temporaryPath))
            {
                SecureFile.DestroyPrefixAndSuffixAndDelete(
                    temporaryPath,
                    RecoverySidecarDestructionBytes,
                    RecoverySidecarDestructionBytes);
            }
        }
    }

    private async Task<RecoveryRepairResult> RepairCoreAsync(
        string archivePath,
        RecoveryProtectionMode expectedMode,
        bool authenticateMetadata,
        bool emergencyMode,
        string? userPassword,
        string? pin,
        string? firstGeneratedPassword,
        string? secondGeneratedPassword,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        string fullArchivePath = Path.GetFullPath(archivePath);
        if (expectedMode == RecoveryProtectionMode.ErrorCorrectionOnly
            && string.Equals(
                Path.GetExtension(fullArchivePath),
                ".kzpaq",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "A .kzpaq path cannot use the unauthenticated plain KPAR2 profile. This may be a downgrade attempt.");
        }

        string recoveryPath = GetRecoveryPath(fullArchivePath);
        if (!File.Exists(recoveryPath))
        {
            return new RecoveryRepairResult(
                false,
                true,
                false,
                0,
                "No KPAR2 recovery file was found.",
                fullArchivePath,
                false,
                null,
                emergencyMode);
        }

        if (expectedMode == RecoveryProtectionMode.DualAuthenticatedEncrypted
            && (userPassword is null || pin is null || firstGeneratedPassword is null || secondGeneratedPassword is null))
        {
            throw new ArgumentException("All four credentials are required for encrypted KPAR2 recovery.");
        }

        string? candidatePath = null;
        bool candidateCompleted = false;
        bool candidateCreatedByThisOperation = false;
        try
        {
#if KEEPVAULT_MACOS
            using MacPrivateFileSnapshot recoverySnapshot = await MacPrivateFileSnapshot
                .CaptureAsync(recoveryPath, cancellationToken)
                .ConfigureAwait(false);
            FileStream recovery = recoverySnapshot.Stream;
#else
            await using FileStream recovery = OpenRecoveryForRead(recoveryPath);
#endif
            RecoveryPackage package = await ReadRecoveryPackageAsync(
                recovery,
                expectedMode,
                authenticateMetadata,
                emergencyMode ? null : Path.GetFileName(fullArchivePath),
                userPassword,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                cancellationToken).ConfigureAwait(false);

#if KEEPVAULT_MACOS
            using MacPrivateFileSnapshot archiveSnapshot = await MacPrivateFileSnapshot
                .CaptureAsync(fullArchivePath, cancellationToken)
                .ConfigureAwait(false);
            FileStream archive = archiveSnapshot.Stream;
#else
            await using FileStream archive = new FileStream(
                fullArchivePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                bufferSize: 1024 * 1024,
                FileOptions.RandomAccess);
#endif
            if (archive.Length != package.Manifest.ArchiveLength)
            {
                throw new InvalidDataException(
                    "KPAR2 refuses archive-length changes. Recovery is limited to damaged blocks inside the original file length.");
            }

            if (expectedMode == RecoveryProtectionMode.ErrorCorrectionOnly
                && await HasEncryptedContainerMagicAsync(
                    archive,
                    cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidDataException(
                    "An encrypted container cannot be recovered through the unauthenticated plain KPAR2 profile.");
            }

            bool archiveHealthy;
            try
            {
                archiveHealthy = await ArchiveMatchesManifestAsync(
                    archive,
                    package.Manifest,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                archiveHealthy = false;
                progress?.Report(
                    "The source archive contains unreadable I/O regions; KPAR2 will copy around them into a new candidate.");
            }
            if (archiveHealthy && !emergencyMode)
            {
                progress?.Report("KPAR2 verification: archive is unchanged.");
                return new RecoveryRepairResult(
                    true,
                    true,
                    false,
                    0,
                    package.AuthenticationVerified
                        ? "Archive and authenticated KPAR2 metadata are valid."
                        : "Archive matches the KPAR2 error-correction checksums; no authenticity claim is made.",
                    fullArchivePath,
                    package.AuthenticationVerified,
                    package.Locator.ProtectionMode,
                    emergencyMode);
            }

            candidatePath = SuggestRecoveredPath(fullArchivePath, emergencyMode);
            progress?.Report(
                emergencyMode
                    ? "Unauthenticated emergency recovery is writing a new candidate; the original remains unchanged."
                    : "KPAR2 detected damaged blocks; a verified recovery candidate is being created.");

            await using (var candidate = new FileStream(
                candidatePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1024 * 1024,
                FileOptions.RandomAccess | FileOptions.WriteThrough))
            {
                candidateCreatedByThisOperation = true;
                int unreadableBlocks = await CopyArchiveForRecoveryAsync(
                    archive,
                    candidate,
                    package.Manifest.ArchiveLength,
                    cancellationToken).ConfigureAwait(false);
                if (unreadableBlocks > 0)
                {
                    progress?.Report(
                        $"KPAR2 candidate copy replaced {unreadableBlocks} unreadable 4096-byte source block(s) with zeros before RS repair.");
                }

                if (candidate.Length != package.Manifest.ArchiveLength)
                {
                    throw new InvalidDataException("The recovery candidate length changed while it was copied.");
                }

                int repairedShards = 0;
                foreach (RecoverySection section in package.Manifest.Sections)
                {
                    repairedShards += await RepairSectionAsync(
                        candidate,
                        recovery,
                        section,
                        cancellationToken).ConfigureAwait(false);
                }

                await candidate.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) makes repaired shards durable before success is reported.
                candidate.Flush(flushToDisk: true);
#pragma warning restore CA1849

                if (!await ArchiveMatchesManifestAsync(candidate, package.Manifest, cancellationToken).ConfigureAwait(false))
                {
                    throw new InvalidDataException(
                        "KPAR2 recovery failed: the candidate does not match both expected archive digests.");
                }

                if (package.Locator.ProtectionMode == RecoveryProtectionMode.ErrorCorrectionOnly
                    && await HasEncryptedContainerMagicAsync(
                        candidate,
                        cancellationToken).ConfigureAwait(false))
                {
                    throw new InvalidDataException(
                        "KPAR2 profile downgrade detected: a plain recovery profile produced an encrypted container.");
                }

                if (package.Locator.ProtectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                    && emergencyMode)
                {
                    await _containers.VerifyAuthenticationAsync(
                        candidate,
                        userPassword!,
                        pin!,
                        firstGeneratedPassword!,
                        secondGeneratedPassword!,
                        cancellationToken).ConfigureAwait(false);
                }

                if (package.Locator.ProtectionMode == RecoveryProtectionMode.ErrorCorrectionOnly)
                {
                    await _archiveIntegrity.CreateFromVerifiedDigestsAsync(
                        candidatePath,
                        package.Manifest.ArchiveSha3_512,
                        package.Manifest.ArchiveSkein1024,
                        cancellationToken).ConfigureAwait(false);
                }

                candidateCompleted = true;
                progress?.Report($"KPAR2 recovery completed: {repairedShards} shard(s), output {candidatePath}");
                return new RecoveryRepairResult(
                    true,
                    archiveHealthy,
                    repairedShards > 0,
                    repairedShards,
                    emergencyMode
                        ? "Emergency recovery completed in a new file; the original was not modified."
                        : package.AuthenticationVerified
                            ? "Authenticated recovery completed in a new verified file."
                            : "Error-correction recovery completed in a new file; no authenticity claim is made.",
                    candidatePath,
                    package.AuthenticationVerified,
                    package.Locator.ProtectionMode,
                    emergencyMode);
            }
        }
        finally
        {
            if (candidateCreatedByThisOperation
                && !candidateCompleted
                && candidatePath is not null)
            {
                ArchiveIntegrityService.DeleteManifests(candidatePath);
                SecureFile.DeleteIfExists(candidatePath);
            }
        }
    }

    private async Task<RecoveryPackage> ReadRecoveryPackageAsync(
        FileStream recovery,
        RecoveryProtectionMode expectedMode,
        bool authenticateMetadata,
        string? expectedArchiveFileName,
        string? userPassword,
        string? pin,
        string? firstGeneratedPassword,
        string? secondGeneratedPassword,
        CancellationToken cancellationToken)
    {
        RecoveryLocator locator = await ReadConsensusLocatorAsync(recovery, cancellationToken).ConfigureAwait(false);
        if (locator.ProtectionMode != expectedMode)
        {
            throw new InvalidOperationException(
                locator.ProtectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                    ? "This encrypted archive requires dual-authenticated KPAR2 recovery with all password factors."
                    : "This KPAR2 file provides error correction only and must not be treated as authenticated.");
        }

        byte[] envelope = await ReadEncodedMetadataAsync(recovery, locator, cancellationToken).ConfigureAwait(false);
        byte[]? payload = null;
        byte[]? expectedSha3 = null;
        byte[]? expectedSkein = null;
        RecoveryKeys? recoveryKeys = null;
        try
        {
            (payload, expectedSha3, expectedSkein) = ParseMetadataEnvelope(envelope, locator.ProtectionMode);
            bool authenticationVerified = false;
            if (authenticateMetadata)
            {
                if (locator.ProtectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
                {
                    recoveryKeys = await DeriveRecoveryKeysAsync(
                        userPassword!,
                        pin!,
                        firstGeneratedPassword!,
                        secondGeneratedPassword!,
                        locator,
                        cancellationToken).ConfigureAwait(false);
                }

                (byte[] actualSha3, byte[] actualSkein) = ComputeMetadataCertification(
                    locator,
                    payload,
                    recoveryKeys);
                try
                {
                    bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3);
                    bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein);
                    if (!(sha3Matches & skeinMatches))
                    {
                        throw locator.ProtectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                            ? new CryptographicException(
                                "Wrong password factors or manipulated dual-authenticated KPAR2 metadata.")
                            : new InvalidDataException(
                                "KPAR2 metadata checksum mismatch. This unencrypted profile does not provide authenticity.");
                    }

                    authenticationVerified = locator.ProtectionMode
                        == RecoveryProtectionMode.DualAuthenticatedEncrypted;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actualSha3);
                    CryptographicOperations.ZeroMemory(actualSkein);
                }
            }

            RecoveryManifest manifest = DeserializeCanonicalManifest(payload);
            ValidateManifest(manifest, locator, expectedArchiveFileName);
            return new RecoveryPackage(locator, manifest, authenticationVerified);
        }
        finally
        {
            recoveryKeys?.Dispose();
            CryptographicOperations.ZeroMemory(envelope);
            ZeroIfNotNull(payload);
            ZeroIfNotNull(expectedSha3);
            ZeroIfNotNull(expectedSkein);
        }
    }

    /// <summary>
    /// Whether a locator's numeric suite id names a suite this build knows.
    /// Asked of the catalogue instead of a hard-coded id range: the range form
    /// only ever admitted the first two suites, so every suite added later was
    /// refused here even though the container itself accepted it.
    /// </summary>
    private static bool IsKnownLocatorSuite(int encryptionSuite) =>
        Enum.IsDefined((EncryptionSuite)encryptionSuite)
        && EncryptionSuiteCatalog.IsKnown((EncryptionSuite)encryptionSuite);

    private async Task<RecoveryKeys> DeriveRecoveryKeysAsync(
        string userPassword,
        string pin,
        string firstGeneratedPassword,
        string secondGeneratedPassword,
        RecoveryLocator locator,
        CancellationToken cancellationToken)
    {
        if (locator.ProtectionMode != RecoveryProtectionMode.DualAuthenticatedEncrypted
            || !IsKnownLocatorSuite(locator.EncryptionSuite)
            || locator.Salt.Length != ExpectedLocatorSaltBytes(locator.EncryptionSuite))
        {
            throw new InvalidDataException("KPAR2 has no valid encrypted KDF bootstrap parameters.");
        }

        var suite = (EncryptionSuite)locator.EncryptionSuite;
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);

        // KPAR2 v3 runs the suite's complete key derivation, both rounds
        // included. KPAR2 v2 ran a single Argon2id round even for the two-round
        // suite, which handed anyone holding both key-sheet factors a cheaper
        // offline oracle for the passphrase through the recovery file than
        // through the container it protects. The certification keys are still
        // separate from the container's -- they come from their own role
        // purposes -- but they now cost exactly as much to attack.
        bool paranoia = parameters.UsesTwoKdfRounds;
        var salts = new V10Salts(
            locator.Salt[..V10Salts.SaltBytes],
            locator.Salt[V10Salts.SaltBytes..SaltPairBytes],
            paranoia ? locator.Salt[SaltPairBytes..(SaltPairBytes + V10Salts.SaltBytes)] : null,
            paranoia ? locator.Salt[(SaltPairBytes + V10Salts.SaltBytes)..] : null);
        salts.Validate(paranoia);
        using V10KeyDerivation.MasterResult master = await Task.Run(
            () => V10KeyDerivation.DeriveMaster(
                parameters,
                userPassword,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                salts,
                progress: null,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        byte[] parentSha3Key = SuiteKeySchedule.DeriveGlobalKey(
            master.Master.Bytes,
            parameters.Algorithm,
            "KPAR2/HMAC-SHA3-512",
            KeyRolePurpose.RecoverySha3Certification,
            parameters.Sha3MacKeyBytes);
        byte[] parentSkeinKey = SuiteKeySchedule.DeriveGlobalKey(
            master.Master.Bytes,
            parameters.Algorithm,
            "KPAR2/Skein-MAC-1024-1024",
            KeyRolePurpose.RecoverySkeinCertification,
            parameters.SkeinMacKeyBytes);
        byte[] sha3Message = BuildKeyDerivationMessage(Sha3KeyDomain, locator);
        byte[] skeinMessage = BuildKeyDerivationMessage(SkeinKeyDomain, locator);
        try
        {
            byte[] sha3Key;
            using (var hmac = new HmacSha3_512(parentSha3Key))
            {
                hmac.AppendData(sha3Message);
                sha3Key = hmac.GetHashAndReset();
            }

            byte[] skeinKey = NativeThreefish.MacSkein1024Reference(parentSkeinKey, skeinMessage);
            try
            {
                return new RecoveryKeys(sha3Key, skeinKey);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(sha3Key);
                CryptographicOperations.ZeroMemory(skeinKey);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parentSha3Key);
            CryptographicOperations.ZeroMemory(parentSkeinKey);
            CryptographicOperations.ZeroMemory(sha3Message);
            CryptographicOperations.ZeroMemory(skeinMessage);
        }
    }

    private static byte[] BuildKeyDerivationMessage(byte[] domain, RecoveryLocator locator)
    {
        byte[] result = new byte[
            sizeof(int) + domain.Length
            + sizeof(int) + locator.ArchiveId.Length
            + sizeof(int) + sizeof(int)];
        int offset = 0;
        WriteLengthAndBytes(result, ref offset, domain);
        WriteLengthAndBytes(result, ref offset, locator.ArchiveId);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), Version);
        offset += sizeof(int);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset), locator.EncryptionSuite);
        return result;
    }

    private static (byte[] Sha3, byte[] Skein) ComputeMetadataCertification(
        RecoveryLocator locator,
        byte[] payload,
        RecoveryKeys? keys)
    {
        byte[] prefix = BuildCertificationPrefix(locator, payload.Length);
        try
        {
            if (locator.ProtectionMode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
            {
                if (keys is null)
                {
                    throw new CryptographicException("Authenticated KPAR2 certification requires recovery MAC keys.");
                }

                byte[] sha3;
                using (var hmac = new HmacSha3_512(keys.Sha3Key))
                {
                    hmac.AppendData(prefix);
                    hmac.AppendData(payload);
                    sha3 = hmac.GetHashAndReset();
                }

                using NativeSkein1024Mac skeinMac = NativeThreefish.CreateSkeinMac(keys.SkeinKey);
                skeinMac.AppendData(prefix);
                skeinMac.AppendData(payload);
                return (sha3, skeinMac.GetTag());
            }

            using var sha3Hash = new Sha3_512Incremental();
            using var skeinHash = new Skein1024Digest();
            sha3Hash.AppendData(prefix);
            sha3Hash.AppendData(payload);
            skeinHash.AppendData(prefix);
            skeinHash.AppendData(payload);
            return (sha3Hash.GetHashAndReset(), skeinHash.GetHashAndReset());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
        }
    }

    private static byte[] BuildCertificationPrefix(RecoveryLocator locator, int payloadLength)
    {
        byte[] context = BuildLocatorCertificationContext(locator);
        byte[] result = new byte[
            sizeof(int) + CertificationDomain.Length
            + sizeof(int) + context.Length
            + sizeof(long)];
        try
        {
            int offset = 0;
            WriteLengthAndBytes(result, ref offset, CertificationDomain);
            WriteLengthAndBytes(result, ref offset, context);
            BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(offset), payloadLength);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(context);
        }
    }

    private static byte[] BuildLocatorCertificationContext(RecoveryLocator locator)
    {
        // Sized from the widest salt a locator may carry, not from a number
        // that happened to fit when the salt was 512 bits wide.
        byte[] result = new byte[LocatorCertificationContextFixedBytes + LocatorSaltBytes];
        int offset = 0;
        WriteInt32(result, ref offset, Version);
        WriteInt32(result, ref offset, (int)locator.ProtectionMode);
        WriteInt32(result, ref offset, LocatorBlockSize);
        WriteInt32(result, ref offset, DataShardCount);
        WriteInt32(result, ref offset, ParityShardCount);
        WriteInt64(result, ref offset, locator.MetadataOffset);
        WriteInt64(result, ref offset, locator.MetadataEncodedLength);
        WriteInt64(result, ref offset, locator.MetadataEnvelopeLength);
        WriteInt32(result, ref offset, locator.MetadataStripeCount);
        WriteInt64(result, ref offset, locator.ArchiveLength);
        WriteInt32(result, ref offset, locator.EncryptionSuite);
        WriteInt32(result, ref offset, locator.Salt.Length);
        locator.ArchiveId.CopyTo(result, offset);
        offset += 32;
        locator.Salt.CopyTo(result, offset);
        offset += locator.Salt.Length;
        return result.AsSpan(0, offset).ToArray();
    }

    private static byte[] BuildMetadataEnvelope(
        RecoveryProtectionMode protectionMode,
        byte[] payload,
        byte[] sha3Certification,
        byte[] skeinCertification)
    {
        if (sha3Certification.Length != Sha3_512Compat.HashSizeInBytes
            || skeinCertification.Length != Skein1024Digest.DigestSize)
        {
            throw new CryptographicException("KPAR2 certification has an invalid length.");
        }

        byte[] envelope = new byte[checked(MetadataEnvelopeHeaderSize + payload.Length)];
        MetadataEnvelopeMagic.CopyTo(envelope, 0);
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(8), Version);
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(12), (int)protectionMode);
        BinaryPrimitives.WriteInt64LittleEndian(envelope.AsSpan(16), payload.Length);
        sha3Certification.CopyTo(envelope, 24);
        skeinCertification.CopyTo(envelope, 24 + Sha3_512Compat.HashSizeInBytes);
        payload.CopyTo(envelope, MetadataEnvelopeHeaderSize);
        return envelope;
    }

    private static (byte[] Payload, byte[] Sha3, byte[] Skein) ParseMetadataEnvelope(
        byte[] envelope,
        RecoveryProtectionMode expectedMode)
    {
        if (envelope.Length < MetadataEnvelopeHeaderSize
            || !envelope.AsSpan(0, 8).SequenceEqual(MetadataEnvelopeMagic)
            || BinaryPrimitives.ReadInt32LittleEndian(envelope.AsSpan(8)) != Version
            || BinaryPrimitives.ReadInt32LittleEndian(envelope.AsSpan(12)) != (int)expectedMode)
        {
            throw new InvalidDataException("KPAR2 metadata envelope header is invalid.");
        }

        long payloadLength = BinaryPrimitives.ReadInt64LittleEndian(envelope.AsSpan(16));
        if (payloadLength <= 0
            || payloadLength != envelope.Length - MetadataEnvelopeHeaderSize)
        {
            throw new InvalidDataException("KPAR2 metadata envelope length is invalid.");
        }

        return (
            envelope.AsSpan(MetadataEnvelopeHeaderSize).ToArray(),
            envelope.AsSpan(24, Sha3_512Compat.HashSizeInBytes).ToArray(),
            envelope.AsSpan(24 + Sha3_512Compat.HashSizeInBytes, Skein1024Digest.DigestSize).ToArray());
    }

    private static async Task<RecoverySection> CreateSectionAsync(
        FileStream archive,
        FileStream recovery,
        string name,
        long offset,
        long length,
        int shardSize,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var section = new RecoverySection
        {
            Name = name,
            Offset = offset,
            Length = length,
            ShardSize = shardSize,
            DataShardCount = DataShardCount,
            ParityShardCount = ParityShardCount,
            StripeCount = checked((int)DivideRoundUp(
                length,
                (long)DataShardCount * shardSize)),
        };

        progress?.Report($"Recovery {name}: {section.StripeCount} stripe(s), RS(20,3), 15% redundancy ...");
        byte[][] data = AllocateShards(DataShardCount, shardSize);
        byte[][] parity = AllocateShards(ParityShardCount, shardSize);
        try
        {
            for (int stripe = 0; stripe < section.StripeCount; stripe++)
            {
                ZeroShards(parity);
                for (int dataIndex = 0; dataIndex < DataShardCount; dataIndex++)
                {
                    long shardOffset = offset + (((long)stripe * DataShardCount + dataIndex) * shardSize);
                    await ReadArchiveShardAsync(
                        archive,
                        shardOffset,
                        offset + length,
                        data[dataIndex],
                        cancellationToken).ConfigureAwait(false);
                    section.DataDigests.Add(DualDigestBase64(data[dataIndex]));
                }

                ComputeParity(data, parity, cancellationToken);
                for (int parityIndex = 0; parityIndex < ParityShardCount; parityIndex++)
                {
                    long parityOffset = recovery.Position;
                    await recovery.WriteAsync(parity[parityIndex], cancellationToken).ConfigureAwait(false);
                    section.Parity.Add(new RecoveryParityShard(
                        stripe,
                        parityIndex,
                        parityOffset,
                        shardSize,
                        DualDigestBase64(parity[parityIndex])));
                }
            }
        }
        finally
        {
            ZeroShards(data);
            ZeroShards(parity);
        }

        return section;
    }

    private static async Task<int> RepairSectionAsync(
        FileStream archive,
        FileStream recovery,
        RecoverySection section,
        CancellationToken cancellationToken)
    {
        int repaired = 0;
        byte[][] data = AllocateShards(section.DataShardCount, section.ShardSize);
        byte[][] parity = AllocateShards(section.ParityShardCount, section.ShardSize);
        try
        {
            for (int stripe = 0; stripe < section.StripeCount; stripe++)
            {
                var badData = new List<int>();
                var goodParity = new List<int>();
                for (int dataIndex = 0; dataIndex < section.DataShardCount; dataIndex++)
                {
                    long shardOffset = section.Offset
                        + (((long)stripe * section.DataShardCount + dataIndex) * section.ShardSize);
                    await ReadArchiveShardAsync(
                        archive,
                        shardOffset,
                        section.Offset + section.Length,
                        data[dataIndex],
                        cancellationToken).ConfigureAwait(false);
                    string expected = section.DataDigests[(stripe * section.DataShardCount) + dataIndex];
                    if (!DualDigestMatches(data[dataIndex], expected))
                    {
                        badData.Add(dataIndex);
                    }
                }

                if (badData.Count == 0)
                {
                    continue;
                }

                if (badData.Count > section.ParityShardCount)
                {
                    throw new InvalidDataException(
                        $"KPAR2 cannot repair stripe {stripe} in {section.Name}: {badData.Count} bad data shards, but only {section.ParityShardCount} parity shards.");
                }

                for (int parityIndex = 0; parityIndex < section.ParityShardCount; parityIndex++)
                {
                    RecoveryParityShard parityInfo = section.Parity[
                        (stripe * section.ParityShardCount) + parityIndex];
                    bool readable = await TryReadAtAsync(
                        recovery,
                        parityInfo.Offset,
                        parity[parityIndex],
                        cancellationToken).ConfigureAwait(false);
                    if (readable && DualDigestMatches(parity[parityIndex], parityInfo.Digest))
                    {
                        goodParity.Add(parityIndex);
                    }
                }

                if (goodParity.Count < badData.Count)
                {
                    throw new InvalidDataException(
                        $"KPAR2 cannot repair stripe {stripe} in {section.Name}: {badData.Count} bad data shards and only {goodParity.Count} valid parity shards.");
                }

                RecoverBadShards(data, parity, badData, goodParity.Take(badData.Count).ToArray());
                foreach (int dataIndex in badData)
                {
                    string expected = section.DataDigests[(stripe * section.DataShardCount) + dataIndex];
                    if (!DualDigestMatches(data[dataIndex], expected))
                    {
                        throw new InvalidDataException(
                            $"KPAR2 reconstructed an invalid shard: {section.Name}, stripe {stripe}, shard {dataIndex}.");
                    }

                    long shardOffset = section.Offset
                        + (((long)stripe * section.DataShardCount + dataIndex) * section.ShardSize);
                    await WriteArchiveShardAsync(
                        archive,
                        shardOffset,
                        section.Offset + section.Length,
                        data[dataIndex],
                        cancellationToken).ConfigureAwait(false);
                    repaired++;
                }
            }
        }
        finally
        {
            ZeroShards(data);
            ZeroShards(parity);
        }

        return repaired;
    }

    private static async Task WriteEncodedMetadataAsync(
        FileStream recovery,
        byte[] envelope,
        RecoveryLocator locator,
        CancellationToken cancellationToken)
    {
        if (recovery.Position != locator.MetadataOffset)
        {
            throw new InvalidDataException("Internal KPAR2 metadata offset mismatch.");
        }

        long envelopeOffset = 0;
        for (int stripe = 0; stripe < locator.MetadataStripeCount; stripe++)
        {
            byte[][] data = AllocateShards(DataShardCount, MetadataPayloadSize);
            byte[][] parity = AllocateShards(ParityShardCount, MetadataPayloadSize);
            try
            {
                int[] payloadLengths = new int[DataShardCount];
                for (int dataIndex = 0; dataIndex < DataShardCount; dataIndex++)
                {
                    int count = (int)Math.Min(MetadataPayloadSize, envelope.Length - envelopeOffset);
                    if (count > 0)
                    {
                        envelope.AsSpan((int)envelopeOffset, count).CopyTo(data[dataIndex]);
                        envelopeOffset += count;
                    }

                    payloadLengths[dataIndex] = count;
                }

                ComputeParity(data, parity, cancellationToken);
                for (int dataIndex = 0; dataIndex < DataShardCount; dataIndex++)
                {
                    await WriteMetadataBlockAsync(
                        recovery,
                        stripe,
                        dataIndex,
                        isParity: false,
                        payloadLengths[dataIndex],
                        data[dataIndex],
                        cancellationToken).ConfigureAwait(false);
                }

                for (int parityIndex = 0; parityIndex < ParityShardCount; parityIndex++)
                {
                    await WriteMetadataBlockAsync(
                        recovery,
                        stripe,
                        DataShardCount + parityIndex,
                        isParity: true,
                        MetadataPayloadSize,
                        parity[parityIndex],
                        cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                ZeroShards(data);
                ZeroShards(parity);
            }
        }

        if (envelopeOffset != envelope.Length
            || recovery.Position != locator.MetadataOffset + locator.MetadataEncodedLength)
        {
            throw new InvalidDataException("Internal KPAR2 metadata encoding length mismatch.");
        }
    }

    private static async Task WriteMetadataBlockAsync(
        FileStream recovery,
        int stripe,
        int shardIndex,
        bool isParity,
        int payloadLength,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        byte[] block = new byte[LocatorBlockSize];
        byte[]? sha3 = null;
        byte[]? skein = null;
        try
        {
            MetadataBlockMagic.CopyTo(block, 0);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(8), Version);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(12), stripe);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(16), shardIndex);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(20), isParity ? 1 : 0);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(24), payloadLength);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(28), 0);
            payload.CopyTo(block, MetadataBlockHeaderSize);
            (sha3, skein) = ComputeDualHash(block.AsSpan(0, MetadataBlockSkeinOffset));
            skein.CopyTo(block, MetadataBlockSkeinOffset);
            sha3.CopyTo(block, MetadataBlockSha3Offset);
            await recovery.WriteAsync(block, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            ZeroIfNotNull(sha3);
            ZeroIfNotNull(skein);
        }
    }

    private static async Task<byte[]> ReadEncodedMetadataAsync(
        FileStream recovery,
        RecoveryLocator locator,
        CancellationToken cancellationToken)
    {
        byte[] envelope = new byte[locator.MetadataEnvelopeLength];
        long envelopeOffset = 0;
        byte[] block = new byte[LocatorBlockSize];
        try
        {
            for (int stripe = 0; stripe < locator.MetadataStripeCount; stripe++)
            {
                byte[][] data = AllocateShards(DataShardCount, MetadataPayloadSize);
                byte[][] parity = AllocateShards(ParityShardCount, MetadataPayloadSize);
                var badData = new List<int>();
                var goodParity = new List<int>();
                try
                {
                    for (int shardIndex = 0; shardIndex < DataShardCount + ParityShardCount; shardIndex++)
                    {
                        long blockOffset = checked(
                            locator.MetadataOffset
                            + (((long)stripe * (DataShardCount + ParityShardCount) + shardIndex)
                                * LocatorBlockSize));
                        bool readable = await TryReadAtAsync(
                            recovery,
                            blockOffset,
                            block,
                            cancellationToken).ConfigureAwait(false);

                        bool isParity = shardIndex >= DataShardCount;
                        int expectedPayloadLength = isParity
                            ? MetadataPayloadSize
                            : ExpectedMetadataPayloadLength(
                                locator.MetadataEnvelopeLength,
                                stripe,
                                shardIndex);
                        bool valid = readable && ValidateMetadataBlock(
                            block,
                            stripe,
                            shardIndex,
                            isParity,
                            expectedPayloadLength);
                        if (valid)
                        {
                            if (isParity)
                            {
                                block.AsSpan(MetadataBlockHeaderSize, MetadataPayloadSize)
                                    .CopyTo(parity[shardIndex - DataShardCount]);
                                goodParity.Add(shardIndex - DataShardCount);
                            }
                            else
                            {
                                block.AsSpan(MetadataBlockHeaderSize, MetadataPayloadSize)
                                    .CopyTo(data[shardIndex]);
                            }
                        }
                        else if (!isParity)
                        {
                            badData.Add(shardIndex);
                        }

                        CryptographicOperations.ZeroMemory(block);
                    }

                    if (badData.Count > ParityShardCount || goodParity.Count < badData.Count)
                    {
                        throw new InvalidDataException(
                            $"KPAR2 metadata stripe {stripe} exceeds RS(20,3): {badData.Count} bad data blocks and {goodParity.Count} valid parity blocks.");
                    }

                    if (badData.Count > 0)
                    {
                        RecoverBadShards(
                            data,
                            parity,
                            badData,
                            goodParity.Take(badData.Count).ToArray());
                    }

                    for (int dataIndex = 0; dataIndex < DataShardCount; dataIndex++)
                    {
                        int count = ExpectedMetadataPayloadLength(
                            locator.MetadataEnvelopeLength,
                            stripe,
                            dataIndex);
                        if (count > 0)
                        {
                            data[dataIndex].AsSpan(0, count).CopyTo(envelope.AsSpan((int)envelopeOffset));
                            envelopeOffset += count;
                        }
                    }
                }
                finally
                {
                    ZeroShards(data);
                    ZeroShards(parity);
                }
            }

            if (envelopeOffset != envelope.Length)
            {
                throw new InvalidDataException("KPAR2 metadata reconstruction produced an invalid length.");
            }

            (byte[] actualSha3, byte[] actualSkein) = ComputeDualHash(envelope);
            try
            {
                bool sha3Matches = CryptographicOperations.FixedTimeEquals(locator.EnvelopeSha3, actualSha3);
                bool skeinMatches = CryptographicOperations.FixedTimeEquals(locator.EnvelopeSkein, actualSkein);
                if (!(sha3Matches & skeinMatches))
                {
                    throw new InvalidDataException(
                        "KPAR2 metadata could not be reconstructed to its dual locator digest.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualSha3);
                CryptographicOperations.ZeroMemory(actualSkein);
            }

            return envelope;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    private static bool ValidateMetadataBlock(
        byte[] block,
        int stripe,
        int shardIndex,
        bool isParity,
        int expectedPayloadLength)
    {
        bool headerValid = block.AsSpan(0, 8).SequenceEqual(MetadataBlockMagic)
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(8)) == Version
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(12)) == stripe
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(16)) == shardIndex
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(20)) == (isParity ? 1 : 0)
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(24)) == expectedPayloadLength
            && BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(28)) == 0;

        (byte[] actualSha3, byte[] actualSkein) = ComputeDualHash(
            block.AsSpan(0, MetadataBlockSkeinOffset));
        try
        {
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(
                block.AsSpan(MetadataBlockSha3Offset, Sha3_512Compat.HashSizeInBytes),
                actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(
                block.AsSpan(MetadataBlockSkeinOffset, Skein1024Digest.DigestSize),
                actualSkein);
            return headerValid & sha3Matches & skeinMatches;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    private static int ExpectedMetadataPayloadLength(long envelopeLength, int stripe, int dataIndex)
    {
        long payloadOffset = ((long)stripe * DataShardCount + dataIndex) * MetadataPayloadSize;
        return (int)Math.Clamp(envelopeLength - payloadOffset, 0, MetadataPayloadSize);
    }

    private static async Task<RecoveryLocator> ReadConsensusLocatorAsync(
        FileStream recovery,
        CancellationToken cancellationToken)
    {
        if (recovery.Length < PrefixLocatorBytes + SuffixLocatorBytes
            + ((DataShardCount + ParityShardCount) * LocatorBlockSize))
        {
            throw new InvalidDataException("KPAR2 file is too short for the v2 redundant layout.");
        }

        var validBlocks = new List<byte[]>();
        byte[] block = new byte[LocatorBlockSize];
        try
        {
            for (int i = 0; i < PrefixLocatorCopies + SuffixLocatorCopies; i++)
            {
                long offset = i < PrefixLocatorCopies
                    ? (long)i * LocatorBlockSize
                    : recovery.Length - SuffixLocatorBytes
                        + ((long)(i - PrefixLocatorCopies) * LocatorBlockSize);
                bool readable = await TryReadAtAsync(
                    recovery,
                    offset,
                    block,
                    cancellationToken).ConfigureAwait(false);
                if (readable && TryParseLocator(block, recovery.Length, out _))
                {
                    validBlocks.Add(block.ToArray());
                }

                CryptographicOperations.ZeroMemory(block);
            }

            byte[]? consensus = null;
            int consensusCount = 0;
            foreach (byte[] candidate in validBlocks)
            {
                int count = validBlocks.Count(other => candidate.AsSpan().SequenceEqual(other));
                if (count > consensusCount)
                {
                    consensus = candidate;
                    consensusCount = count;
                }
            }

            if (consensus is null || consensusCount < RequiredLocatorConsensus)
            {
                throw new InvalidDataException(
                    "KPAR2 locator consensus failed. At least five of eight self-checking locator blocks must agree.");
            }

            if (!TryParseLocator(consensus, recovery.Length, out RecoveryLocator? locator)
                || locator is null)
            {
                throw new InvalidDataException("KPAR2 locator consensus is internally invalid.");
            }

            return locator;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            foreach (byte[] validBlock in validBlocks)
            {
                CryptographicOperations.ZeroMemory(validBlock);
            }
        }
    }

    private static byte[] BuildLocatorBlock(RecoveryLocator locator)
    {
        ValidateLocator(locator, checked(locator.MetadataOffset + locator.MetadataEncodedLength + SuffixLocatorBytes));
        byte[] block = new byte[LocatorBlockSize];
        byte[]? sha3 = null;
        byte[]? skein = null;
        try
        {
            LocatorMagic.CopyTo(block, 0);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(8), Version);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(12), (int)locator.ProtectionMode);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(16), LocatorBlockSize);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(20), DataShardCount);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(24), ParityShardCount);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(28), 0);
            BinaryPrimitives.WriteInt64LittleEndian(block.AsSpan(32), locator.MetadataOffset);
            BinaryPrimitives.WriteInt64LittleEndian(block.AsSpan(40), locator.MetadataEncodedLength);
            BinaryPrimitives.WriteInt64LittleEndian(block.AsSpan(48), locator.MetadataEnvelopeLength);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(56), locator.MetadataStripeCount);
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(60), locator.EncryptionSuite);
            BinaryPrimitives.WriteInt64LittleEndian(block.AsSpan(64), locator.ArchiveLength);
            // 72..84 stay zero: they carried the Argon2id cost in v2, and a
            // v10 cost is secret-derived. Writing it here would hand an
            // attacker the PMI the container itself refuses to store.
            BinaryPrimitives.WriteInt32LittleEndian(block.AsSpan(84), locator.Salt.Length);
            locator.ArchiveId.CopyTo(block, 88);
            locator.Salt.CopyTo(block, 120);
            locator.EnvelopeSha3.CopyTo(block, 376);
            locator.EnvelopeSkein.CopyTo(block, 440);
            (sha3, skein) = ComputeDualHash(block.AsSpan(0, LocatorAuthenticatedBytes));
            skein.CopyTo(block, LocatorSkeinOffset);
            sha3.CopyTo(block, LocatorSha3Offset);
            return block;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(block);
            throw;
        }
        finally
        {
            ZeroIfNotNull(sha3);
            ZeroIfNotNull(skein);
        }
    }

    private static bool TryParseLocator(
        byte[] block,
        long recoveryLength,
        out RecoveryLocator? locator)
    {
        locator = null;
        if (block.Length != LocatorBlockSize)
        {
            return false;
        }

        (byte[] actualSha3, byte[] actualSkein) = ComputeDualHash(
            block.AsSpan(0, LocatorAuthenticatedBytes));
        try
        {
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(
                block.AsSpan(LocatorSha3Offset, Sha3_512Compat.HashSizeInBytes),
                actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(
                block.AsSpan(LocatorSkeinOffset, Skein1024Digest.DigestSize),
                actualSkein);
            if (!(sha3Matches & skeinMatches)
                || !block.AsSpan(0, 8).SequenceEqual(LocatorMagic)
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(8)) != Version
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(16)) != LocatorBlockSize
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(20)) != DataShardCount
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(24)) != ParityShardCount
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(28)) != 0
                || BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(72)) != 0
                || BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(80)) != 0
                || block.AsSpan(568, LocatorAuthenticatedBytes - 568).IndexOfAnyExcept((byte)0) >= 0)
            {
                return false;
            }

            int saltLength = BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(84));
            if (saltLength is not (0 or SaltPairBytes or LocatorSaltBytes))
            {
                return false;
            }

            if (block.AsSpan(120 + saltLength, LocatorSaltBytes - saltLength)
                .IndexOfAnyExcept((byte)0) >= 0)
            {
                return false;
            }

            locator = new RecoveryLocator(
                (RecoveryProtectionMode)BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(12)),
                BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(32)),
                BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(40)),
                checked((int)BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(48))),
                BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(56)),
                BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(64)),
                BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(60)),
                block.AsSpan(88, 32).ToArray(),
                block.AsSpan(120, saltLength).ToArray(),
                block.AsSpan(376, Sha3_512Compat.HashSizeInBytes).ToArray(),
                block.AsSpan(440, Skein1024Digest.DigestSize).ToArray());
            ValidateLocator(locator, recoveryLength);
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            locator = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    private static void ValidateLocator(RecoveryLocator locator, long recoveryLength)
    {
        if (locator.ProtectionMode is not (
                RecoveryProtectionMode.ErrorCorrectionOnly
                or RecoveryProtectionMode.DualAuthenticatedEncrypted)
            || locator.ArchiveLength is < 0 or > MaxArchiveBytes
            || locator.ArchiveId.Length != 32
            || locator.ArchiveId.All(value => value == 0)
            || locator.EnvelopeSha3.Length != Sha3_512Compat.HashSizeInBytes
            || locator.EnvelopeSkein.Length != Skein1024Digest.DigestSize
            || locator.MetadataOffset < PrefixLocatorBytes
            || locator.MetadataOffset % RecoveryBlockAlignment != 0
            || locator.MetadataEnvelopeLength is <= MetadataEnvelopeHeaderSize or > MaxMetadataEnvelopeBytes
            || locator.MetadataStripeCount <= 0)
        {
            throw new InvalidDataException("KPAR2 locator contains invalid bounded fields.");
        }

        int expectedStripes = checked((int)DivideRoundUp(
            locator.MetadataEnvelopeLength,
            (long)DataShardCount * MetadataPayloadSize));
        long expectedEncodedLength = checked(
            (long)expectedStripes
            * (DataShardCount + ParityShardCount)
            * LocatorBlockSize);
        long expectedFileLength = checked(
            locator.MetadataOffset + expectedEncodedLength + SuffixLocatorBytes);
        if (locator.MetadataStripeCount != expectedStripes
            || locator.MetadataEncodedLength != expectedEncodedLength
            || locator.MetadataEncodedLength > MaxEncodedMetadataBytes
            || recoveryLength != expectedFileLength)
        {
            throw new InvalidDataException("KPAR2 locator geometry is inconsistent with the file length.");
        }

        if (locator.ProtectionMode == RecoveryProtectionMode.ErrorCorrectionOnly)
        {
            if (locator.EncryptionSuite != -1 || locator.Salt.Length != 0)
            {
                throw new InvalidDataException("Plain KPAR2 locator unexpectedly contains encrypted KDF parameters.");
            }
        }
        else if (!IsKnownLocatorSuite(locator.EncryptionSuite)
            || locator.Salt.Length != ExpectedLocatorSaltBytes(locator.EncryptionSuite))
        {
            throw new InvalidDataException("Encrypted KPAR2 locator has invalid suite or salt parameters.");
        }
    }

    private static RecoveryManifest DeserializeCanonicalManifest(byte[] payload)
    {
        try
        {
            RecoveryManifest manifest = JsonSerializer.Deserialize(payload, RecoveryJsonContext.Default.RecoveryManifest)
                ?? throw new InvalidDataException("KPAR2 manifest could not be read.");
            byte[] canonical = JsonSerializer.SerializeToUtf8Bytes(manifest, RecoveryJsonContext.Default.RecoveryManifest);
            try
            {
                if (!payload.AsSpan().SequenceEqual(canonical))
                {
                    throw new InvalidDataException("KPAR2 manifest is not in its unique canonical JSON representation.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }

            return manifest;
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("KPAR2 manifest is not valid canonical JSON.", ex);
        }
    }

    private static void ValidateManifest(
        RecoveryManifest manifest,
        RecoveryLocator locator,
        string? expectedArchiveFileName)
    {
        if (manifest.Version != Version
            || !string.Equals(manifest.Algorithm, RecoveryAlgorithm, StringComparison.Ordinal)
            || manifest.ProtectionMode != locator.ProtectionMode
            || manifest.ArchiveLength != locator.ArchiveLength
            || manifest.RedundancyPercent != 15
            || !IsHexDigest(manifest.ArchiveSha3_512, Sha3_512Compat.HashSizeInBytes)
            || !IsHexDigest(manifest.ArchiveSkein1024, Skein1024Digest.DigestSize)
            || !IsBase64Length(manifest.ArchiveId, 32)
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(manifest.ArchiveId),
                locator.ArchiveId)
            || string.IsNullOrWhiteSpace(manifest.ArchiveFileName)
            || manifest.ArchiveFileName.Length > 255
            || manifest.ArchiveFileName.Any(char.IsControl)
            || !string.Equals(
                manifest.ArchiveFileName,
                Path.GetFileName(manifest.ArchiveFileName),
                StringComparison.Ordinal)
            || (expectedArchiveFileName is not null
                && !string.Equals(
                    manifest.ArchiveFileName,
                    expectedArchiveFileName,
                    StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException("KPAR2 manifest does not match its authenticated locator context.");
        }

        if (locator.ProtectionMode == RecoveryProtectionMode.ErrorCorrectionOnly)
        {
            if (manifest.EncryptionSuite != -1
                || manifest.EncryptionAlgorithm is not null
                || manifest.Salt is not null
                || manifest.Argon2MemoryKiB != 0
                || manifest.Argon2Iterations != 0
                || manifest.Argon2Parallelism != 0
                || manifest.Salt is not null)
            {
                throw new InvalidDataException("Plain KPAR2 manifest contains encrypted KDF metadata.");
            }
        }
        else
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(
                (EncryptionSuite)locator.EncryptionSuite);
            if (manifest.EncryptionSuite != locator.EncryptionSuite
                || !string.Equals(manifest.EncryptionAlgorithm, parameters.Algorithm, StringComparison.Ordinal)
                || !IsBase64Length(manifest.Salt, ExpectedLocatorSaltBytes(locator.EncryptionSuite))
                || !CryptographicOperations.FixedTimeEquals(
                    Convert.FromBase64String(manifest.Salt!),
                    locator.Salt))
            {
                throw new InvalidDataException("Encrypted KPAR2 manifest and locator KDF parameters differ.");
            }
        }

        if (manifest.Sections is null
            || (manifest.ArchiveLength == 0 && manifest.Sections.Count != 0)
            || (manifest.ArchiveLength > 0 && manifest.Sections.Count is < 1 or > 2))
        {
            throw new InvalidDataException("KPAR2 manifest has an invalid archive section structure.");
        }

        long nextArchiveOffset = 0;
        long nextParityOffset = PrefixLocatorBytes;
        for (int sectionIndex = 0; sectionIndex < manifest.Sections.Count; sectionIndex++)
        {
            RecoverySection section = manifest.Sections[sectionIndex]
                ?? throw new InvalidDataException("KPAR2 manifest contains an empty section.");
            string expectedName = sectionIndex == 0 ? "Header" : "Archive";
            if (!string.Equals(section.Name, expectedName, StringComparison.Ordinal)
                || section.DataShardCount != DataShardCount
                || section.ParityShardCount != ParityShardCount
                || section.ShardSize is < MinimumRecoveryShardSize or > BodyShardSize
                || section.ShardSize % RecoveryBlockAlignment != 0
                || section.Offset != nextArchiveOffset
                || section.Length <= 0
                || section.Offset > manifest.ArchiveLength - section.Length)
            {
                throw new InvalidDataException("KPAR2 manifest has an invalid RS(20,3) section profile.");
            }

            long stripeSpan = checked((long)section.DataShardCount * section.ShardSize);
            int expectedStripes = checked((int)DivideRoundUp(section.Length, stripeSpan));
            if (section.StripeCount != expectedStripes
                || section.DataDigests is null
                || section.DataDigests.Count != checked(section.StripeCount * section.DataShardCount)
                || section.Parity is null
                || section.Parity.Count != checked(section.StripeCount * section.ParityShardCount)
                || section.DataDigests.Any(digest => !IsDualDigestBase64(digest)))
            {
                throw new InvalidDataException("KPAR2 manifest has inconsistent stripe digest lists.");
            }

            int parityEntry = 0;
            for (int stripe = 0; stripe < section.StripeCount; stripe++)
            {
                for (int parityIndex = 0; parityIndex < section.ParityShardCount; parityIndex++)
                {
                    RecoveryParityShard parity = section.Parity[parityEntry++];
                    if (parity.Stripe != stripe
                        || parity.ParityIndex != parityIndex
                        || parity.Length != section.ShardSize
                        || parity.Offset != nextParityOffset
                        || nextParityOffset > locator.MetadataOffset - section.ShardSize
                        || !IsDualDigestBase64(parity.Digest))
                    {
                        throw new InvalidDataException("KPAR2 manifest has an invalid parity region.");
                    }

                    nextParityOffset = checked(nextParityOffset + section.ShardSize);
                }
            }

            nextArchiveOffset = checked(nextArchiveOffset + section.Length);
        }

        if (nextArchiveOffset != manifest.ArchiveLength
            || nextParityOffset != locator.MetadataOffset)
        {
            throw new InvalidDataException("KPAR2 manifest does not exactly cover archive and parity regions.");
        }
    }

    private static async Task<bool> ArchiveMatchesManifestAsync(
        FileStream archive,
        RecoveryManifest manifest,
        CancellationToken cancellationToken)
    {
        archive.Position = 0;
        (byte[] actualSha3, byte[] actualSkein) = await IntegrityService.HashStreamAsync(
            archive,
            cancellationToken).ConfigureAwait(false);
        byte[] expectedSha3 = Convert.FromHexString(manifest.ArchiveSha3_512);
        byte[] expectedSkein = Convert.FromHexString(manifest.ArchiveSkein1024);
        try
        {
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein);
            return sha3Matches & skeinMatches;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
        }
    }

    private static bool DualDigestMatches(byte[] data, string expectedDigest)
    {
        if (!TryDecodeDualDigest(expectedDigest, out byte[] expectedSha3, out byte[] expectedSkein))
        {
            return false;
        }

        (byte[] actualSha3, byte[] actualSkein) = ComputeDualHash(data);
        try
        {
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein);
            return sha3Matches & skeinMatches;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    private static string DualDigestBase64(byte[] data)
    {
        (byte[] sha3, byte[] skein) = ComputeDualHash(data);
        try
        {
            return $"{Convert.ToBase64String(sha3)}:{Convert.ToBase64String(skein)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    private static bool IsDualDigestBase64(string? value)
    {
        if (value is null || !TryDecodeDualDigest(value, out byte[] sha3, out byte[] skein))
        {
            return false;
        }

        CryptographicOperations.ZeroMemory(sha3);
        CryptographicOperations.ZeroMemory(skein);
        return true;
    }

    private static bool TryDecodeDualDigest(
        string value,
        out byte[] sha3,
        out byte[] skein)
    {
        sha3 = [];
        skein = [];
        int separator = value.IndexOf(":", StringComparison.Ordinal);
        if (separator <= 0
            || value.IndexOf(":", separator + 1, StringComparison.Ordinal) >= 0)
        {
            return false;
        }

        try
        {
            sha3 = Convert.FromBase64String(value[..separator]);
            skein = Convert.FromBase64String(value[(separator + 1)..]);
            if (sha3.Length != Sha3_512Compat.HashSizeInBytes
                || skein.Length != Skein1024Digest.DigestSize)
            {
                CryptographicOperations.ZeroMemory(sha3);
                CryptographicOperations.ZeroMemory(skein);
                sha3 = [];
                skein = [];
                return false;
            }

            return true;
        }
        catch (FormatException)
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
            sha3 = [];
            skein = [];
            return false;
        }
    }

    private static (byte[] Sha3, byte[] Skein) ComputeDualHash(ReadOnlySpan<byte> data)
    {
        return (Sha3_512Compat.HashData(data), Skein1024Digest.HashData(data));
    }

    private static bool IsHexDigest(string? value, int byteLength)
    {
        return value is not null
            && value.Length == byteLength * 2
            && value.All(Uri.IsHexDigit);
    }

    private static bool IsBase64Length(string? value, int expectedLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(value);
            try
            {
                return decoded.Length == expectedLength;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static async Task<bool> HasEncryptedContainerMagicAsync(
        FileStream input,
        CancellationToken cancellationToken)
    {
        if (input.Length < 7)
        {
            return false;
        }

        byte[] magic = new byte[7];
        try
        {
            input.Position = 0;
            await input.ReadExactlyAsync(magic, cancellationToken).ConfigureAwait(false);
            return magic.AsSpan().SequenceEqual("KZPAQ1\0"u8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
        }
    }

    private static async Task<long> DetectHeaderLengthAsync(
        FileStream input,
        long archiveLength,
        CancellationToken cancellationToken)
    {
        if (archiveLength < 11)
        {
            return archiveLength;
        }

        input.Position = 0;
        byte[] prefix = new byte[7];
        byte[] lengthBytes = new byte[sizeof(int)];
        try
        {
            await input.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
            if (prefix.AsSpan().SequenceEqual("KZPAQ1\0"u8))
            {
                await input.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
                int headerLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
                if (headerLength is > 0 and <= 16 * 1024)
                {
                    return Math.Min(
                        archiveLength,
                        7L + sizeof(int) + headerLength
                        + Sha3_512Compat.HashSizeInBytes
                        + Skein1024Digest.DigestSize);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(lengthBytes);
        }

        return Math.Min(archiveLength, PlainHeaderBytes);
    }

    private static FileStream OpenRecoveryForRead(string recoveryPath)
    {
#if KEEPVAULT_MACOS
        return MacSafeFileSystem.OpenReadNoSymlinks(recoveryPath);
#else
        return new FileStream(
            recoveryPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            FileOptions.RandomAccess);
#endif
    }

    private static string SuggestRecoveredPath(string archivePath, bool emergency)
    {
        string directory = Path.GetDirectoryName(archivePath) ?? Environment.CurrentDirectory;
        string extension = Path.GetExtension(archivePath);
        string stem = Path.GetFileNameWithoutExtension(archivePath);
        string marker = emergency ? ".emergency-recovered" : ".recovered";
        string candidate = Path.Combine(directory, $"{stem}{marker}{extension}");
        for (int suffix = 1; File.Exists(candidate) || Directory.Exists(candidate); suffix++)
        {
            candidate = Path.Combine(directory, $"{stem}{marker} ({suffix}){extension}");
        }

        return candidate;
    }

    private static async Task WriteZeroBytesAsync(
        FileStream stream,
        int count,
        CancellationToken cancellationToken)
    {
        byte[] zeroBlock = new byte[LocatorBlockSize];
        try
        {
            int remaining = count;
            while (remaining > 0)
            {
                int write = Math.Min(remaining, zeroBlock.Length);
                await stream.WriteAsync(zeroBlock.AsMemory(0, write), cancellationToken).ConfigureAwait(false);
                remaining -= write;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeroBlock);
        }
    }

    private static async Task<int> CopyArchiveForRecoveryAsync(
        FileStream source,
        FileStream destination,
        long length,
        CancellationToken cancellationToken)
    {
        byte[] chunk = new byte[RecoveryCopyChunkBytes];
        byte[] block = new byte[RecoveryBlockAlignment];
        int unreadableBlocks = 0;
        try
        {
            for (long chunkOffset = 0; chunkOffset < length; chunkOffset += chunk.Length)
            {
                int chunkLength = (int)Math.Min(chunk.Length, length - chunkOffset);
                bool chunkReadable = await TryReadAtAsync(
                    source,
                    chunkOffset,
                    chunk.AsMemory(0, chunkLength),
                    cancellationToken).ConfigureAwait(false);
                if (chunkReadable)
                {
                    destination.Position = chunkOffset;
                    await destination.WriteAsync(
                        chunk.AsMemory(0, chunkLength),
                        cancellationToken).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(chunk.AsSpan(0, chunkLength));
                    continue;
                }

                for (int relativeOffset = 0; relativeOffset < chunkLength; relativeOffset += block.Length)
                {
                    int blockLength = Math.Min(block.Length, chunkLength - relativeOffset);
                    long sourceOffset = chunkOffset + relativeOffset;
                    bool blockReadable = await TryReadAtAsync(
                        source,
                        sourceOffset,
                        block.AsMemory(0, blockLength),
                        cancellationToken).ConfigureAwait(false);
                    if (!blockReadable)
                    {
                        CryptographicOperations.ZeroMemory(block.AsSpan(0, blockLength));
                        unreadableBlocks++;
                    }

                    destination.Position = sourceOffset;
                    await destination.WriteAsync(
                        block.AsMemory(0, blockLength),
                        cancellationToken).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(block.AsSpan(0, blockLength));
                }
            }

            return unreadableBlocks;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(chunk);
            CryptographicOperations.ZeroMemory(block);
        }
    }

    private static async Task<bool> TryReadAtAsync(
        FileStream stream,
        long offset,
        byte[] destination,
        CancellationToken cancellationToken)
    {
        return await TryReadAtAsync(
            stream,
            offset,
            destination.AsMemory(),
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> TryReadAtAsync(
        FileStream stream,
        long offset,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        CryptographicOperations.ZeroMemory(destination.Span);
        try
        {
            int total = 0;
            while (total < destination.Length)
            {
                int read = await RandomAccess.ReadAsync(
                    stream.SafeFileHandle,
                    destination[total..],
                    checked(offset + total),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    CryptographicOperations.ZeroMemory(destination.Span);
                    return false;
                }

                total += read;
            }

            return true;
        }
        catch (IOException)
        {
            CryptographicOperations.ZeroMemory(destination.Span);
            return false;
        }
    }

    private static int ChooseHeaderShardSize(long headerLength)
    {
        return RoundUpToBlock((int)Math.Clamp(
            DivideRoundUp(headerLength, DataShardCount),
            MinimumRecoveryShardSize,
            64 * 1024));
    }

    private static int ChooseBodyShardSize(long bodyLength)
    {
        if (bodyLength <= 0)
        {
            return 0;
        }

        if (bodyLength < (long)DataShardCount * BodyShardSize)
        {
            return RoundUpToBlock((int)Math.Clamp(
                DivideRoundUp(bodyLength, DataShardCount),
                MinimumRecoveryShardSize,
                BodyShardSize));
        }

        return BodyShardSize;
    }

    private static int RoundUpToBlock(int value)
    {
        return checked(
            (value + RecoveryBlockAlignment - 1)
            / RecoveryBlockAlignment
            * RecoveryBlockAlignment);
    }

    private static long AlignUp(long value, int alignment)
    {
        return value <= 0 ? 0 : checked(DivideRoundUp(value, alignment) * alignment);
    }

    private static long DivideRoundUp(long value, long divisor)
    {
        if (value < 0 || divisor <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return value == 0 ? 0 : checked(((value - 1) / divisor) + 1);
    }

    private static async Task ReadArchiveShardAsync(
        FileStream archive,
        long shardOffset,
        long sectionEnd,
        byte[] destination,
        CancellationToken cancellationToken)
    {
        Array.Clear(destination);
        if (shardOffset >= sectionEnd)
        {
            return;
        }

        int toRead = (int)Math.Min(destination.Length, sectionEnd - shardOffset);
        archive.Position = shardOffset;
        int total = 0;
        while (total < toRead)
        {
            int read = await archive.ReadAsync(
                destination.AsMemory(total, toRead - total),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException(
                    "The archive ended before a complete KPAR2 data shard could be read.");
            }

            total += read;
        }
    }

    private static async Task WriteArchiveShardAsync(
        FileStream archive,
        long shardOffset,
        long sectionEnd,
        byte[] source,
        CancellationToken cancellationToken)
    {
        if (shardOffset >= sectionEnd)
        {
            return;
        }

        int toWrite = (int)Math.Min(source.Length, sectionEnd - shardOffset);
        archive.Position = shardOffset;
        await archive.WriteAsync(source.AsMemory(0, toWrite), cancellationToken).ConfigureAwait(false);
    }

    private static void RecoverBadShards(
        byte[][] data,
        byte[][] parity,
        IReadOnlyList<int> badData,
        IReadOnlyList<int> parityRows)
    {
        if (badData.Count == 0)
        {
            return;
        }

        if (badData.Count > parity.Length || parityRows.Count != badData.Count)
        {
            throw new InvalidDataException("Too many damaged shards for available KPAR2 parity.");
        }

        int missingCount = badData.Count;
        byte[][] syndromes = AllocateShards(missingCount, parity[0].Length);
        byte[,] matrix = new byte[missingCount, missingCount];
        try
        {
            for (int equation = 0; equation < missingCount; equation++)
            {
                int parityIndex = parityRows[equation];
                Buffer.BlockCopy(
                    parity[parityIndex],
                    0,
                    syndromes[equation],
                    0,
                    parity[parityIndex].Length);
                for (int dataIndex = 0; dataIndex < data.Length; dataIndex++)
                {
                    if (badData.Contains(dataIndex))
                    {
                        continue;
                    }

                    XorScaledInto(
                        syndromes[equation],
                        data[dataIndex],
                        GfPow((byte)(dataIndex + 1), parityIndex));
                }

                for (int missingIndex = 0; missingIndex < missingCount; missingIndex++)
                {
                    matrix[equation, missingIndex] = GfPow(
                        (byte)(badData[missingIndex] + 1),
                        parityIndex);
                }
            }

            byte[,] inverse = InvertMatrix(matrix, missingCount);
            for (int missingIndex = 0; missingIndex < missingCount; missingIndex++)
            {
                byte[] recovered = data[badData[missingIndex]];
                CryptographicOperations.ZeroMemory(recovered);
                for (int parityIndex = 0; parityIndex < missingCount; parityIndex++)
                {
                    XorScaledInto(
                        recovered,
                        syndromes[parityIndex],
                        inverse[missingIndex, parityIndex]);
                }
            }
        }
        finally
        {
            ZeroShards(syndromes);
        }
    }

    private static byte[][] AllocateShards(int count, int shardSize)
    {
        byte[][] shards = new byte[count][];
        for (int i = 0; i < shards.Length; i++)
        {
            shards[i] = new byte[shardSize];
        }

        return shards;
    }

    private static void ZeroShards(byte[][] shards)
    {
        foreach (byte[] shard in shards)
        {
            CryptographicOperations.ZeroMemory(shard);
        }
    }

    private static void XorInto(byte[] target, byte[] source)
    {
        int index = 0;
        int vectorLength = Vector<byte>.Count;
        for (; index <= target.Length - vectorLength; index += vectorLength)
        {
            (new Vector<byte>(target, index) ^ new Vector<byte>(source, index)).CopyTo(target, index);
        }

        for (; index < target.Length; index++)
        {
            target[index] ^= source[index];
        }
    }

    private static void XorScaledInto(byte[] target, byte[] source, byte coefficient)
    {
        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= GfMul(coefficient, source[i]);
        }
    }

    private static void XorScaledInto(byte[] target, byte[] source, byte[] multiplicationTable)
    {
        for (int index = 0; index < target.Length; index++)
        {
            target[index] ^= multiplicationTable[source[index]];
        }
    }

    private static void ComputeParity(
        byte[][] data,
        byte[][] parity,
        CancellationToken cancellationToken)
    {
        void ComputeRow(int parityIndex)
        {
            for (int dataIndex = 0; dataIndex < data.Length; dataIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte coefficient = GfPow((byte)(dataIndex + 1), parityIndex);
                if (coefficient == 1)
                {
                    XorInto(parity[parityIndex], data[dataIndex]);
                }
                else
                {
                    XorScaledInto(
                        parity[parityIndex],
                        data[dataIndex],
                        ParityMultiplicationTables[(parityIndex * DataShardCount) + dataIndex]);
                }
            }
        }

        if (data[0].Length < 256 * 1024)
        {
            for (int parityIndex = 0; parityIndex < parity.Length; parityIndex++)
            {
                ComputeRow(parityIndex);
            }

            return;
        }

        Parallel.For(
            0,
            parity.Length,
            new ParallelOptions
            {
                CancellationToken = cancellationToken,
                MaxDegreeOfParallelism = ParityShardCount,
            },
            ComputeRow);
    }

    private static byte GfMul(byte a, byte b)
    {
        if (a == 0 || b == 0)
        {
            return 0;
        }

        return GfExp[GfLog[a] + GfLog[b]];
    }

    private static byte GfDiv(byte a, byte b)
    {
        if (b == 0)
        {
            throw new DivideByZeroException("GF(256) division by zero.");
        }

        if (a == 0)
        {
            return 0;
        }

        return GfExp[GfLog[a] + 255 - GfLog[b]];
    }

    private static byte GfPow(byte value, int exponent)
    {
        if (exponent == 0)
        {
            return 1;
        }

        if (value == 0)
        {
            return 0;
        }

        return GfExp[(GfLog[value] * exponent) % 255];
    }

    private static byte[,] InvertMatrix(byte[,] matrix, int size)
    {
        byte[,] augmented = new byte[size, size * 2];
        for (int row = 0; row < size; row++)
        {
            for (int column = 0; column < size; column++)
            {
                augmented[row, column] = matrix[row, column];
            }

            augmented[row, size + row] = 1;
        }

        for (int pivot = 0; pivot < size; pivot++)
        {
            int pivotRow = pivot;
            while (pivotRow < size && augmented[pivotRow, pivot] == 0)
            {
                pivotRow++;
            }

            if (pivotRow == size)
            {
                throw new InvalidDataException("KPAR2 recovery equation is singular.");
            }

            if (pivotRow != pivot)
            {
                for (int column = 0; column < size * 2; column++)
                {
                    (augmented[pivot, column], augmented[pivotRow, column])
                        = (augmented[pivotRow, column], augmented[pivot, column]);
                }
            }

            byte pivotInverse = GfDiv(1, augmented[pivot, pivot]);
            for (int column = 0; column < size * 2; column++)
            {
                augmented[pivot, column] = GfMul(
                    augmented[pivot, column],
                    pivotInverse);
            }

            for (int row = 0; row < size; row++)
            {
                if (row == pivot)
                {
                    continue;
                }

                byte factor = augmented[row, pivot];
                if (factor == 0)
                {
                    continue;
                }

                for (int column = 0; column < size * 2; column++)
                {
                    augmented[row, column] ^= GfMul(
                        factor,
                        augmented[pivot, column]);
                }
            }
        }

        byte[,] inverse = new byte[size, size];
        for (int row = 0; row < size; row++)
        {
            for (int column = 0; column < size; column++)
            {
                inverse[row, column] = augmented[row, size + column];
            }
        }

        return inverse;
    }

    private static void WriteLengthAndBytes(byte[] destination, ref int offset, byte[] value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination.AsSpan(offset), value.Length);
        offset += sizeof(int);
        value.CopyTo(destination, offset);
        offset += value.Length;
    }

    private static void WriteInt32(byte[] destination, ref int offset, int value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination.AsSpan(offset), value);
        offset += sizeof(int);
    }

    private static void WriteInt64(byte[] destination, ref int offset, long value)
    {
        BinaryPrimitives.WriteInt64LittleEndian(destination.AsSpan(offset), value);
        offset += sizeof(long);
    }

    private static void ZeroIfNotNull(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static readonly byte[] GfExp = BuildGfExp();
    private static readonly byte[] GfLog = BuildGfLog(GfExp);
    private static readonly byte[][] ParityMultiplicationTables = BuildParityMultiplicationTables();

    private static byte[] BuildGfExp()
    {
        byte[] exp = new byte[512];
        int x = 1;
        for (int i = 0; i < 255; i++)
        {
            exp[i] = (byte)x;
            x <<= 1;
            if ((x & 0x100) != 0)
            {
                x ^= 0x11d;
            }
        }

        for (int i = 255; i < exp.Length; i++)
        {
            exp[i] = exp[i - 255];
        }

        return exp;
    }

    private static byte[] BuildGfLog(byte[] exp)
    {
        byte[] log = new byte[256];
        for (int i = 0; i < 255; i++)
        {
            log[exp[i]] = (byte)i;
        }

        return log;
    }

    private static byte[][] BuildParityMultiplicationTables()
    {
        var tables = new byte[ParityShardCount * DataShardCount][];
        for (int parityIndex = 0; parityIndex < ParityShardCount; parityIndex++)
        {
            for (int dataIndex = 0; dataIndex < DataShardCount; dataIndex++)
            {
                byte coefficient = GfPow((byte)(dataIndex + 1), parityIndex);
                byte[] table = new byte[256];
                for (int value = 0; value < table.Length; value++)
                {
                    table[value] = GfMul(coefficient, (byte)value);
                }

                tables[(parityIndex * DataShardCount) + dataIndex] = table;
            }
        }

        return tables;
    }

    [JsonSourceGenerationOptions(
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        WriteIndented = false,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        GenerationMode = JsonSourceGenerationMode.Metadata)]
    [JsonSerializable(typeof(RecoveryManifest))]
    private sealed partial class RecoveryJsonContext : JsonSerializerContext;

    private sealed class RecoveryKeys : IDisposable
    {
        private readonly IDisposable _sha3Lock;
        private readonly IDisposable _skeinLock;
        private bool _disposed;

        public RecoveryKeys(byte[] sha3Key, byte[] skeinKey)
        {
            if (sha3Key.Length != Sha3_512Compat.HashSizeInBytes
                || skeinKey.Length != Skein1024Digest.MacKeySize)
            {
                throw new CryptographicException("Derived KPAR2 MAC key length is invalid.");
            }

            Sha3Key = sha3Key;
            SkeinKey = skeinKey;
            IDisposable? sha3Lock = null;
            IDisposable? skeinLock = null;
            try
            {
                sha3Lock = SecureMemory.TryLock(Sha3Key);
                skeinLock = SecureMemory.TryLock(SkeinKey);
                _sha3Lock = sha3Lock;
                _skeinLock = skeinLock;
            }
            catch
            {
                skeinLock?.Dispose();
                sha3Lock?.Dispose();
                CryptographicOperations.ZeroMemory(Sha3Key);
                CryptographicOperations.ZeroMemory(SkeinKey);
                throw;
            }
        }

        public byte[] Sha3Key { get; }

        public byte[] SkeinKey { get; }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CryptographicOperations.ZeroMemory(Sha3Key);
            CryptographicOperations.ZeroMemory(SkeinKey);
            _skeinLock.Dispose();
            _sha3Lock.Dispose();
        }
    }
}

public sealed record RecoveryRepairResult(
    bool RecoveryAvailable,
    bool ArchiveHealthy,
    bool Repaired,
    int RepairedShards,
    string Message,
    string? OutputPath = null,
    bool Authenticated = false,
    RecoveryProtectionMode? ProtectionMode = null,
    bool EmergencyMode = false);

internal sealed record RecoveryLocator(
    RecoveryProtectionMode ProtectionMode,
    long MetadataOffset,
    long MetadataEncodedLength,
    int MetadataEnvelopeLength,
    int MetadataStripeCount,
    long ArchiveLength,
    int EncryptionSuite,
    byte[] ArchiveId,
    byte[] Salt,
    byte[] EnvelopeSha3,
    byte[] EnvelopeSkein);

internal sealed record RecoveryPackage(
    RecoveryLocator Locator,
    RecoveryManifest Manifest,
    bool AuthenticationVerified);

internal sealed class RecoveryManifest
{
    public int Version { get; set; }
    public string Algorithm { get; set; } = string.Empty;
    public RecoveryProtectionMode ProtectionMode { get; set; }
    public string ArchiveFileName { get; set; } = string.Empty;
    public long ArchiveLength { get; set; }
    public string ArchiveSha3_512 { get; set; } = string.Empty;
    public string ArchiveSkein1024 { get; set; } = string.Empty;
    public int RedundancyPercent { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public string ArchiveId { get; set; } = string.Empty;
    public string? EncryptionAlgorithm { get; set; }
    public int EncryptionSuite { get; set; } = -1;
    public string? Salt { get; set; }
    public int Argon2MemoryKiB { get; set; }
    public int Argon2Iterations { get; set; }
    public int Argon2Parallelism { get; set; }
    public List<RecoverySection> Sections { get; set; } = [];
}

internal sealed class RecoverySection
{
    public string Name { get; set; } = string.Empty;
    public long Offset { get; set; }
    public long Length { get; set; }
    public int ShardSize { get; set; }
    public int DataShardCount { get; set; }
    public int ParityShardCount { get; set; }
    public int StripeCount { get; set; }
    public List<string> DataDigests { get; set; } = [];
    public List<RecoveryParityShard> Parity { get; set; } = [];
}

internal sealed record RecoveryParityShard(
    int Stripe,
    int ParityIndex,
    long Offset,
    int Length,
    string Digest);
