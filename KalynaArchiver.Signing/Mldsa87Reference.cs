using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Signing;

public sealed class Mldsa87Reference : IDisposable
{
    private readonly nint _module;
    private readonly KeyPairDelegate _keyPair;
    private readonly SignDelegate _sign;
    private readonly VerifyDelegate _verify;
    private readonly ReferenceCommitDelegate _referenceCommit;
    private bool _disposed;

    public Mldsa87Reference(string libraryPath)
    {
        string fullPath = Path.GetFullPath(libraryPath);
        _module = NativeLibrary.Load(fullPath);
        try
        {
            _keyPair = Marshal.GetDelegateForFunctionPointer<KeyPairDelegate>(
                NativeLibrary.GetExport(_module, "mldsa87_keypair"));
            _sign = Marshal.GetDelegateForFunctionPointer<SignDelegate>(
                NativeLibrary.GetExport(_module, "mldsa87_sign"));
            _verify = Marshal.GetDelegateForFunctionPointer<VerifyDelegate>(
                NativeLibrary.GetExport(_module, "mldsa87_verify"));
            _referenceCommit = Marshal.GetDelegateForFunctionPointer<ReferenceCommitDelegate>(
                NativeLibrary.GetExport(_module, "mldsa87_reference_commit"));
            string commit = Marshal.PtrToStringAnsi(_referenceCommit()) ?? string.Empty;
            if (!string.Equals(
                commit,
                "pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be",
                StringComparison.Ordinal))
            {
                throw new CryptographicException("The ML-DSA reference adapter reports an unexpected source revision.");
            }
        }
        catch
        {
            NativeLibrary.Free(_module);
            throw;
        }
    }

    public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] publicKey = new byte[Mldsa87.PublicKeyBytes];
        byte[] privateKey = new byte[Mldsa87.PrivateKeyBytes];
        int result = _keyPair(publicKey, (nuint)publicKey.Length, privateKey, (nuint)privateKey.Length);
        if (result != 0)
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(privateKey);
            throw new CryptographicException($"The official ML-DSA-87 reference key generator returned {result}.");
        }

        return (publicKey, privateKey);
    }

    public byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (privateKey.Length != Mldsa87.PrivateKeyBytes)
        {
            throw new ArgumentException("Invalid ML-DSA-87 private-key length.", nameof(privateKey));
        }

        byte[] messageCopy = message.ToArray();
        byte[] privateCopy = privateKey.ToArray();
        byte[] context = Mldsa87.SigningContext.ToArray();
        byte[] signature = new byte[Mldsa87.SignatureBytes];
        try
        {
            int result = _sign(
                signature,
                (nuint)signature.Length,
                out nuint signatureLength,
                messageCopy,
                (nuint)messageCopy.Length,
                context,
                (nuint)context.Length,
                privateCopy,
                (nuint)privateCopy.Length);
            if (result != 0 || signatureLength != (nuint)signature.Length)
            {
                throw new CryptographicException($"The official ML-DSA-87 reference signer returned {result}.");
            }

            return signature;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(signature);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageCopy);
            CryptographicOperations.ZeroMemory(privateCopy);
            CryptographicOperations.ZeroMemory(context);
        }
    }

    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (signature.Length != Mldsa87.SignatureBytes || publicKey.Length != Mldsa87.PublicKeyBytes)
        {
            return false;
        }

        byte[] messageCopy = message.ToArray();
        byte[] signatureCopy = signature.ToArray();
        byte[] publicCopy = publicKey.ToArray();
        byte[] context = Mldsa87.SigningContext.ToArray();
        try
        {
            return _verify(
                signatureCopy,
                (nuint)signatureCopy.Length,
                messageCopy,
                (nuint)messageCopy.Length,
                context,
                (nuint)context.Length,
                publicCopy,
                (nuint)publicCopy.Length) == 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageCopy);
            CryptographicOperations.ZeroMemory(signatureCopy);
            CryptographicOperations.ZeroMemory(context);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        NativeLibrary.Free(_module);
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int KeyPairDelegate(byte[] publicKey, nuint publicKeyLength, byte[] privateKey, nuint privateKeyLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int SignDelegate(
        byte[] signature,
        nuint signatureCapacity,
        out nuint signatureLength,
        byte[] message,
        nuint messageLength,
        byte[] context,
        nuint contextLength,
        byte[] privateKey,
        nuint privateKeyLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int VerifyDelegate(
        byte[] signature,
        nuint signatureLength,
        byte[] message,
        nuint messageLength,
        byte[] context,
        nuint contextLength,
        byte[] publicKey,
        nuint publicKeyLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint ReferenceCommitDelegate();
}
