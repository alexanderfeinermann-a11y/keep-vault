using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace KalynaArchiver.Signing;

public static class Mldsa87
{
    public const int PublicKeyBytes = 2592;
    public const int PrivateKeyBytes = 4896;
    public const int SignatureBytes = 4627;

    private static readonly byte[] Context = Encoding.ASCII.GetBytes("KalynaZpaqVault/HybridArtifactSignature/v1");

    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_87));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        var publicKey = (MLDsaPublicKeyParameters)pair.Public;
        var privateKey = (MLDsaPrivateKeyParameters)pair.Private;
        byte[] publicEncoding = publicKey.GetEncoded();
        byte[] privateEncoding = privateKey.GetEncoded();
        if (publicEncoding.Length != PublicKeyBytes || privateEncoding.Length != PrivateKeyBytes)
        {
            CryptographicOperations.ZeroMemory(privateEncoding);
            throw new CryptographicException("ML-DSA-87 key generation returned an unexpected encoding length.");
        }

        return (publicEncoding, privateEncoding);
    }

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        ValidateLength(privateKey.Length, PrivateKeyBytes, "private key");
        byte[] privateCopy = privateKey.ToArray();
        try
        {
            MLDsaPrivateKeyParameters parameters = MLDsaPrivateKeyParameters.FromEncoding(
                MLDsaParameters.ml_dsa_87,
                privateCopy);
            byte[] result = parameters.GetPublicKeyEncoded();
            ValidateLength(result.Length, PublicKeyBytes, "derived public key");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
        }
    }

    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        ValidateLength(privateKey.Length, PrivateKeyBytes, "private key");
        byte[] privateCopy = privateKey.ToArray();
        try
        {
            MLDsaPrivateKeyParameters parameters = MLDsaPrivateKeyParameters.FromEncoding(
                MLDsaParameters.ml_dsa_87,
                privateCopy);
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
            signer.Init(
                true,
                new ParametersWithContext(
                    new ParametersWithRandom(parameters, new SecureRandom()),
                    Context));
            signer.BlockUpdate(message);
            byte[] signature = signer.GenerateSignature();
            ValidateLength(signature.Length, SignatureBytes, "signature");
            return signature;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
        }
    }

    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureBytes || publicKey.Length != PublicKeyBytes)
        {
            return false;
        }

        byte[] publicCopy = publicKey.ToArray();
        byte[] signatureCopy = signature.ToArray();
        try
        {
            MLDsaPublicKeyParameters parameters = MLDsaPublicKeyParameters.FromEncoding(
                MLDsaParameters.ml_dsa_87,
                publicCopy);
            var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_87, deterministic: false);
            verifier.Init(false, new ParametersWithContext(parameters, Context));
            verifier.BlockUpdate(message);
            return verifier.VerifySignature(signatureCopy);
        }
        catch (ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signatureCopy);
        }
    }

    public static ReadOnlySpan<byte> SigningContext => Context;

    private static void ValidateLength(int actual, int expected, string name)
    {
        if (actual != expected)
        {
            throw new ArgumentException($"ML-DSA-87 {name} must contain exactly {expected} bytes.", name);
        }
    }
}
