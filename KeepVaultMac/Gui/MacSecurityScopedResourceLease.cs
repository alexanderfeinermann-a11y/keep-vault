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

    /// <summary>
    /// A lease that holds no scope of its own.
    /// </summary>
    /// <remarks>
    /// Used where access is already held for the duration by a retained lease,
    /// so a second scope would be redundant. Starting one twice and stopping it
    /// once would leak the extension; this makes the borrow explicit instead.
    /// </remarks>
    internal static MacSecurityScopedResourceLease Borrowed() => new(0);

    /// <summary>
    /// Takes ownership of an NSURL that was resolved from a security-scoped
    /// bookmark and starts access on it.
    /// </summary>
    /// <remarks>
    /// Unlike a plain file URL, a bookmark-resolved one genuinely is
    /// security-scoped, so a NO here is a real denial and fails closed. The URL
    /// is retained for the lifetime of the lease because the autorelease pool
    /// that produced it is not under this code's control.
    /// </remarks>
    internal static MacSecurityScopedResourceLease AdoptResolvedUrl(nint url)
    {
        if (url == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(url), "A resolved security-scoped URL is required.");
        }

        nint retained = CFRetain(url);
        if (retained == 0)
        {
            throw new InvalidOperationException("The resolved security-scoped URL could not be retained.");
        }

        if (!ObjcMessageSendBool(retained, StartAccessSelector))
        {
            CFRelease(retained);
            throw new UnauthorizedAccessException(
                "macOS denied access to the resource the panel helper reported as selected.");
        }

        return new MacSecurityScopedResourceLease(retained);
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

            // startAccessingSecurityScopedResource reports NO both when access is
            // refused and when the URL simply is not security-scoped. The latter
            // is the ordinary case here: a drop and an in-process open panel
            // hand over plain file URLs for which the sandbox has already
            // extended access to this process, and only URLs resolved from a
            // security-scoped bookmark ever answer YES. Treating NO as a denial
            // rejected every file the user picked or dropped.
            //
            // Whether access truly exists is therefore established by reading
            // the item, not by this call, and the caller fails closed when the
            // path cannot be reached. Access must also not be stopped for a URL
            // that never started, so an unscoped lease holds no URL to release.
            if (!ObjcMessageSendBool(url, StartAccessSelector))
            {
                return new MacSecurityScopedResourceLease(0);
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
        GC.SuppressFinalize(this);
        nint url = Interlocked.Exchange(ref _url, 0);

        // An unscoped lease holds nothing: stopping access for a URL that never
        // started is an unbalanced call.
        if (url == 0)
        {
            return;
        }

        ObjcMessageSendVoid(url, StopAccessSelector);
        CFRelease(url);
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

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRetain")]
    private static partial nint CFRetain(nint value);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint SelRegisterName(string name);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool ObjcMessageSendBool(nint receiver, nint selector);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial void ObjcMessageSendVoid(nint receiver, nint selector);
}

/// <summary>
/// A retained grant of access to one file or folder.
/// </summary>
/// <remarks>
/// Access arrives by two different routes and the lease has to serve both. A
/// drop delivers an Avalonia storage item; a panel goes through the helper
/// bundle and yields a resolved security-scoped URL with no storage item behind
/// it. The canonical path is therefore what identifies a lease, rather than the
/// object identity of a storage item that only one of the two routes produces.
/// </remarks>
internal sealed class MacStorageAccessLease : IDisposable
{
    private readonly MacSecurityScopedResourceLease _nativeLease;
    private IStorageItem? _item;
    private int _disposed;

    private MacStorageAccessLease(string path, IStorageItem? item, MacSecurityScopedResourceLease nativeLease)
    {
        Path = path;
        _item = item;
        _nativeLease = nativeLease;
    }

    /// <summary>Canonical path this lease grants access to.</summary>
    internal string Path { get; }

    /// <summary>The storage item, when the access came from a drop.</summary>
    internal IStorageItem? Item => _item;

    internal static MacStorageAccessLease Acquire(IStorageItem item, string path)
    {
        MacSecurityScopedResourceLease nativeLease = MacSecurityScopedResourceLease.Acquire(item);
        return new MacStorageAccessLease(path, item, nativeLease);
    }

    /// <summary>Wraps a selection the panel helper produced.</summary>
    internal static MacStorageAccessLease FromResolvedSelection(string path, MacSecurityScopedResourceLease nativeLease)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(nativeLease);
        return new MacStorageAccessLease(path, item: null, nativeLease);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _nativeLease.Dispose();
        Interlocked.Exchange(ref _item, null)?.Dispose();
    }
}
