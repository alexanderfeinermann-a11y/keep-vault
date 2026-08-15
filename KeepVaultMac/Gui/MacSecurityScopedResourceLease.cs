using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Avalonia.Platform.Storage;

namespace KalynaArchiver.Gui;

internal sealed partial class MacSecurityScopedResourceLease : IDisposable
{
    private const uint Utf8Encoding = 0x08000100;
    private static readonly nint StartAccessSelector = SelRegisterName("startAccessingSecurityScopedResource");
    private static readonly nint StopAccessSelector = SelRegisterName("stopAccessingSecurityScopedResource");

    private nint _url;

    private MacSecurityScopedResourceLease(nint url)
    {
        _url = url;
    }

    internal static MacSecurityScopedResourceLease Acquire(IStorageItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return Acquire(item.Path);
    }

    internal static MacSecurityScopedResourceLease Acquire(Uri itemUri)
    {
        ArgumentNullException.ThrowIfNull(itemUri);
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Security-scoped URL leases are only available on macOS.");
        }

        if (!itemUri.IsAbsoluteUri || !itemUri.IsFile)
        {
            throw new NotSupportedException("The selected storage item does not expose an absolute file URL.");
        }

        byte[] uriBytes = System.Text.Encoding.UTF8.GetBytes(itemUri.AbsoluteUri);
        nint uriString = 0;
        nint url = 0;
        try
        {
            uriString = CFStringCreateWithBytes(
                0,
                uriBytes,
                uriBytes.Length,
                Utf8Encoding,
                isExternalRepresentation: false);
            if (uriString == 0)
            {
                throw new InvalidOperationException("Foundation could not create the security-scoped URL string.");
            }

            url = CFURLCreateWithString(0, uriString, 0);
            if (url == 0)
            {
                throw new InvalidOperationException("Foundation could not create the security-scoped file URL.");
            }

            if (!ObjcMessageSendBool(url, StartAccessSelector))
            {
                throw new UnauthorizedAccessException("macOS denied the security-scoped resource lease.");
            }

            nint ownedUrl = url;
            url = 0;
            return new MacSecurityScopedResourceLease(ownedUrl);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(uriBytes);
            if (url != 0)
            {
                CFRelease(url);
            }

            if (uriString != 0)
            {
                CFRelease(uriString);
            }
        }
    }

    public void Dispose()
    {
        nint url = Interlocked.Exchange(ref _url, 0);
        if (url == 0)
        {
            return;
        }

        ObjcMessageSendVoid(url, StopAccessSelector);
        CFRelease(url);
        GC.SuppressFinalize(this);
    }

    ~MacSecurityScopedResourceLease()
    {
        Dispose();
    }

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFStringCreateWithBytes")]
    private static partial nint CFStringCreateWithBytes(
        nint allocator,
        byte[] bytes,
        nint length,
        uint encoding,
        [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFURLCreateWithString")]
    private static partial nint CFURLCreateWithString(nint allocator, nint urlString, nint baseUrl);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
    private static partial void CFRelease(nint value);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint SelRegisterName(string name);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool ObjcMessageSendBool(nint receiver, nint selector);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial void ObjcMessageSendVoid(nint receiver, nint selector);
}

internal sealed class MacStorageAccessLease : IDisposable
{
    private readonly MacSecurityScopedResourceLease _nativeLease;
    private IStorageItem? _item;

    private MacStorageAccessLease(IStorageItem item, MacSecurityScopedResourceLease nativeLease)
    {
        _item = item;
        _nativeLease = nativeLease;
    }

    internal IStorageItem Item => _item
        ?? throw new ObjectDisposedException(nameof(MacStorageAccessLease));

    internal static MacStorageAccessLease Acquire(IStorageItem item)
    {
        MacSecurityScopedResourceLease nativeLease = MacSecurityScopedResourceLease.Acquire(item);
        return new MacStorageAccessLease(item, nativeLease);
    }

    public void Dispose()
    {
        IStorageItem? item = Interlocked.Exchange(ref _item, null);
        if (item is null)
        {
            return;
        }

        _nativeLease.Dispose();
        item.Dispose();
    }
}
