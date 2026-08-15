using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        string command = args[0].ToUpperInvariant();
        Dictionary<string, string> options = ParseOptions(args[1..]);
        return command switch
        {
            "KEYGEN" => RunKeygen(options),
            "SIGN" => await RunSignAsync(options).ConfigureAwait(false),
            "VERIFY" => RunVerify(options),
            "FINGERPRINT" => RunFingerprint(options),
            "REFERENCE-SELF-TEST" => RunReferenceSelfTest(options),
            _ => Usage($"Unknown command: {command}"),
        };
    }
#pragma warning disable CA1031 // The CLI process boundary must turn every signing failure into a nonzero exit code.
    catch (Exception ex)
#pragma warning restore CA1031
    {
        await Console.Error.WriteLineAsync(ex.ToString()).ConfigureAwait(false);
        return 2;
    }
}

static int RunKeygen(Dictionary<string, string> options)
{
    string privatePath = Require(options, "private-key");
    string publicPath = Require(options, "public-key");
    string referencePath = Require(options, "reference-dll");
    MldsaKeyStore.CreateDevelopmentKey(privatePath, publicPath);

    using MldsaPrivateKeyLease key = MldsaKeyStore.OpenDevelopmentKey(privatePath, publicPath);
    using var reference = new Mldsa87Reference(referencePath);
    CrossCheckImplementations(reference, key.PrivateKey, key.PublicKey);
    PrintPublicKeyPins(key.PublicKey);
    Console.WriteLine($"private_key={Path.GetFullPath(privatePath)}");
    Console.WriteLine($"public_key={Path.GetFullPath(publicPath)}");
    return 0;
}

static async Task<int> RunSignAsync(Dictionary<string, string> options)
{
    string filePath = Require(options, "file");
    string privatePath = Require(options, "private-key");
    string publicPath = Require(options, "public-key");
    string referencePath = Require(options, "reference-dll");
    string signaturePath = options.GetValueOrDefault("signature") ?? filePath + HybridSignatureService.SidecarExtension;

    using X509Certificate2 certificate = LoadCertificate(options);
    using MldsaPrivateKeyLease key = MldsaKeyStore.OpenDevelopmentKey(privatePath, publicPath);
    byte[] privateKeyCopy = key.PrivateKey.ToArray();
    byte[] publicKeyCopy = key.PublicKey.ToArray();
    try
    {
        using HybridSignatureCreationResult result = await HybridSignatureService.CreateAsync(
            filePath,
            signaturePath,
            certificate,
            privateKeyCopy,
            publicKeyCopy).ConfigureAwait(false);
        using var reference = new Mldsa87Reference(referencePath);
        if (!reference.Verify(result.Payload, result.MldsaSignature, key.PublicKey))
        {
            throw new CryptographicException("The official ML-DSA-87 reference implementation rejected the generated signature.");
        }

        Console.WriteLine($"signature={Path.GetFullPath(signaturePath)}");
        Console.WriteLine($"sha512={result.Sha512}");
        Console.WriteLine($"rsa_thumbprint={result.RsaThumbprint}");
        Console.WriteLine("mldsa87_reference=verified");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(privateKeyCopy);
        CryptographicOperations.ZeroMemory(publicKeyCopy);
    }
    return 0;
}

static int RunVerify(Dictionary<string, string> options)
{
    string filePath = Require(options, "file");
    string publicPath = Require(options, "public-key");
    string signaturePath = options.GetValueOrDefault("signature") ?? filePath + HybridSignatureService.SidecarExtension;
    byte[] publicKey = ReadExactFile(publicPath, Mldsa87.PublicKeyBytes);
    try
    {
        var policy = new HybridSignaturePolicy(
            Require(options, "rsa-sha256"),
            Require(options, "rsa-sha3"),
            Require(options, "rsa-skein"),
            Require(options, "mldsa-sha256"),
            Require(options, "mldsa-sha3"),
            Require(options, "mldsa-skein"),
            publicKey);
        HybridSignatureVerificationResult result = HybridSignatureService.VerifyFile(filePath, signaturePath, policy);
        Console.WriteLine($"trusted={BoolText(result.IsTrusted)}");
        Console.WriteLine($"rsa_pss_sha512={BoolText(result.RsaPssValid)}");
        Console.WriteLine($"mldsa87={BoolText(result.Mldsa87Valid)}");
        Console.WriteLine($"message={result.Message}");
        return result.IsTrusted ? 0 : 3;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(publicKey);
    }
}

static string BoolText(bool value) => value ? "true" : "false";

static int RunFingerprint(Dictionary<string, string> options)
{
    using var stream = new FileStream(
        Require(options, "file"),
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        bufferSize: 1024 * 1024,
        FileOptions.SequentialScan);
    (byte[] sha256, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(stream);
    try
    {
        Console.WriteLine($"sha256={Convert.ToHexString(sha256)}");
        Console.WriteLine($"sha3_512={Convert.ToHexString(sha3)}");
        Console.WriteLine($"skein1024={Convert.ToHexString(skein)}");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sha256);
        CryptographicOperations.ZeroMemory(sha3);
        CryptographicOperations.ZeroMemory(skein);
    }
}

static int RunReferenceSelfTest(Dictionary<string, string> options)
{
    using var reference = new Mldsa87Reference(Require(options, "reference-dll"));
    (byte[] publicKey, byte[] privateKey) = reference.GenerateKeyPair();
    try
    {
        CrossCheckImplementations(reference, privateKey, publicKey);
        Console.WriteLine("reference_self_test=passed");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(privateKey);
    }
}

static void CrossCheckImplementations(Mldsa87Reference reference, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
{
    byte[] message = SHA512.HashData("KalynaZpaqVault ML-DSA-87 reference cross-check v1"u8);
    byte[]? managedSignature = null;
    byte[]? referenceSignature = null;
    try
    {
        managedSignature = Mldsa87.Sign(message, privateKey);
        if (!reference.Verify(message, managedSignature, publicKey))
        {
            throw new CryptographicException("The official reference implementation rejected the managed ML-DSA-87 signature.");
        }

        referenceSignature = reference.Sign(message, privateKey);
        if (!Mldsa87.Verify(message, referenceSignature, publicKey))
        {
            throw new CryptographicException("The managed ML-DSA-87 verifier rejected the official reference signature.");
        }

        message[0] ^= 0x80;
        if (reference.Verify(message, managedSignature, publicKey)
            || Mldsa87.Verify(message, referenceSignature, publicKey))
        {
            throw new CryptographicException("ML-DSA-87 cross-check accepted a modified message.");
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(message);
        if (managedSignature is not null)
        {
            CryptographicOperations.ZeroMemory(managedSignature);
        }

        if (referenceSignature is not null)
        {
            CryptographicOperations.ZeroMemory(referenceSignature);
        }
    }
}

static void PrintPublicKeyPins(ReadOnlySpan<byte> publicKey)
{
    (byte[] sha256, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(publicKey);
    try
    {
        Console.WriteLine($"mldsa_sha256={Convert.ToHexString(sha256)}");
        Console.WriteLine($"mldsa_sha3_512={Convert.ToHexString(sha3)}");
        Console.WriteLine($"mldsa_skein1024={Convert.ToHexString(skein)}");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sha256);
        CryptographicOperations.ZeroMemory(sha3);
        CryptographicOperations.ZeroMemory(skein);
    }
}

static X509Certificate2 LoadCertificate(Dictionary<string, string> options)
{
    if (options.TryGetValue("certificate-thumbprint", out string? thumbprint))
    {
        string normalized = new(thumbprint.Where(Uri.IsHexDigit).ToArray());
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        X509Certificate2? certificate = store.Certificates
            .Find(X509FindType.FindByThumbprint, normalized, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault(certificate => certificate.HasPrivateKey);
        return certificate is null
            ? throw new CryptographicException("The selected RSA code-signing certificate was not found with a private key.")
            : new X509Certificate2(certificate);
    }

    if (options.TryGetValue("pfx", out string? pfxPath))
    {
        string password = options.TryGetValue("pfx-password-env", out string? environmentName)
            ? Environment.GetEnvironmentVariable(environmentName)
                ?? throw new CryptographicException($"PFX password environment variable is not set: {environmentName}")
            : string.Empty;
        return X509CertificateLoader.LoadPkcs12FromFile(
            pfxPath,
            password,
            X509KeyStorageFlags.EphemeralKeySet);
    }

    throw new ArgumentException("Provide --certificate-thumbprint or --pfx.");
}

static Dictionary<string, string> ParseOptions(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (int index = 0; index < args.Length; index += 2)
    {
        if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
        {
            throw new ArgumentException($"Invalid option near '{args[index]}'. Options require --name value pairs.");
        }

        string name = args[index][2..];
        if (!result.TryAdd(name, args[index + 1]))
        {
            throw new ArgumentException($"Duplicate option: --{name}");
        }
    }

    return result;
}

static string Require(Dictionary<string, string> options, string name)
{
    return options.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new ArgumentException($"Missing required option --{name}.");
}

static byte[] ReadExactFile(string path, int expectedBytes)
{
    using var stream = new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        bufferSize: 4096,
        FileOptions.SequentialScan);
    if (stream.Length != expectedBytes)
    {
        throw new InvalidDataException(
            $"Expected {expectedBytes} bytes in {Path.GetFileName(path)}, found {stream.Length}.");
    }

    byte[] contents = new byte[expectedBytes];
    stream.ReadExactly(contents);
    return contents;
}

static int Usage(string error)
{
    Console.Error.WriteLine(error);
    Console.Error.WriteLine("Commands: keygen, sign, verify, fingerprint, reference-self-test");
    return 1;
}
