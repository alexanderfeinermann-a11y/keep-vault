using System.IO;
using System.IO.IsolatedStorage;
using System.Security;
using System.Text;

namespace KalynaArchiver.Services;

internal interface IAppSettingsStore
{
    string? Read(string key);

    void Write(string key, string value);
}

internal sealed class IsolatedStorageAppSettingsStore : IAppSettingsStore
{
    internal const int MaxValueBytes = 64;
    private const int MaxKeyCharacters = 64;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public string? Read(string key)
    {
        ValidateKey(key);
        try
        {
            using IsolatedStorageFile store = IsolatedStorageFile.GetUserStoreForAssembly();
            if (!store.FileExists(key))
            {
                return null;
            }

            using var stream = new IsolatedStorageFileStream(key, FileMode.Open, FileAccess.Read, FileShare.Read, store);
            if (stream.Length is <= 0 or > MaxValueBytes)
            {
                return null;
            }

            byte[] encoded = new byte[(int)stream.Length];
            stream.ReadExactly(encoded);
            return DecodeValue(encoded);
        }
        catch (IOException)
        {
            return null;
        }
        catch (IsolatedStorageException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (SecurityException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    public void Write(string key, string value)
    {
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        byte[] encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length is <= 0 or > MaxValueBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"A setting value must contain 1 to {MaxValueBytes} UTF-8 bytes.");
        }

        try
        {
            using IsolatedStorageFile store = IsolatedStorageFile.GetUserStoreForAssembly();
            using var stream = new IsolatedStorageFileStream(key, FileMode.Create, FileAccess.Write, FileShare.None, store);
            stream.Write(encoded);
            stream.Flush();
        }
        catch (IOException)
        {
            // Preferences are best effort and must never block startup or archive operations.
        }
        catch (IsolatedStorageException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (SecurityException)
        {
        }
        catch (NotSupportedException)
        {
        }
    }

    internal static string? DecodeValue(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is <= 0 or > MaxValueBytes)
        {
            return null;
        }

        try
        {
            return StrictUtf8.GetString(encoded);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (key.Length > MaxKeyCharacters
            || key.Any(character => character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.')))
        {
            throw new ArgumentException("A settings key contains unsupported characters.", nameof(key));
        }
    }
}
