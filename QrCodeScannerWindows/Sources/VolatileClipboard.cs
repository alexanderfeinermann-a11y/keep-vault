using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace QrScanner;

// The copy button, and the one place a scanned value leaves this process.
//
// Everything else here is arranged so the payload never reaches storage. The
// clipboard is the exception that cannot be argued away: it is owned by the
// system, not by this app, and Windows may keep it in clipboard history and -
// with the cloud clipboard - hand it to the user's other devices. No setting
// available to an application changes that on its own.
//
// What can be done is done. The item carries the three formats Windows itself
// defines for exactly this case, so history, cloud sync and third-party
// clipboard monitors are asked to leave it alone; it is cleared again after a
// short delay; and the delay is stated in the interface rather than left as a
// surprise. What cannot be done is claimed nowhere: see README.md.

public sealed class VolatileClipboard : IDisposable
{
    /// <summary>
    /// Keeps the entry out of the Windows clipboard history (Win+V).
    /// </summary>
    private const string CanIncludeInClipboardHistory = "CanIncludeInClipboardHistory";

    /// <summary>
    /// Keeps the entry from being synchronised to the user's other devices.
    /// </summary>
    private const string CanUploadToCloudClipboard = "CanUploadToCloudClipboard";

    /// <summary>
    /// Asks third-party clipboard managers not to record the entry. A
    /// convention rather than an enforcement, which is why the clearing timer
    /// exists as well.
    /// </summary>
    private const string ExcludeFromMonitorProcessing = "ExcludeClipboardContentFromMonitorProcessing";

    /// <summary>
    /// Long enough to switch windows and paste, short enough that the value is
    /// not still sitting there hours later.
    /// </summary>
    public TimeSpan Lifetime { get; }

    private readonly DispatcherTimer _expiry;
    private uint? _sequenceAtCopy;
    private Action? _onExpiry;
    private bool _disposed;

    public VolatileClipboard(TimeSpan? lifetime = null)
    {
        Lifetime = lifetime ?? TimeSpan.FromSeconds(90);
        _expiry = new DispatcherTimer { Interval = Lifetime };
        _expiry.Tick += (_, _) => ClearIfStillOurs();
    }

    /// <summary>
    /// Puts the payload on the clipboard and schedules its removal.
    /// </summary>
    /// <param name="onExpiry">
    /// Run when the value is cleared, so the interface can stop telling the
    /// user it is available to paste.
    /// </param>
    public void Copy(string payload, Action onExpiry)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(onExpiry);

        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, payload);
        data.SetData(CanIncludeInClipboardHistory, FalseDword());
        data.SetData(CanUploadToCloudClipboard, FalseDword());
        data.SetData(ExcludeFromMonitorProcessing, new MemoryStream());

        // Not the "copy" overload: leaving the data on the clipboard after this
        // process exits would outlive every guarantee made above, and the whole
        // point is that the value has a short life.
        Clipboard.SetDataObject(data, copy: false);

        _sequenceAtCopy = GetClipboardSequenceNumber();
        _onExpiry = onExpiry;
        _expiry.Stop();
        _expiry.Interval = Lifetime;
        _expiry.Start();
    }

    /// <summary>
    /// Removes the value, but only if it is still the one this app put there.
    /// </summary>
    /// <remarks>
    /// The user may well have copied something else in the meantime, and wiping
    /// their current clipboard because a scan expired would be its own small
    /// disaster. The sequence number is what tells the two cases apart.
    /// </remarks>
    public void ClearIfStillOurs()
    {
        _expiry.Stop();
        uint? stamp = _sequenceAtCopy;
        _sequenceAtCopy = null;
        Action? onExpiry = _onExpiry;
        _onExpiry = null;

        if (stamp is not null && GetClipboardSequenceNumber() == stamp)
        {
            try
            {
                Clipboard.Clear();
            }
            catch (Exception exception) when (exception is System.Runtime.InteropServices.ExternalException
                or InvalidOperationException)
            {
                // Another process may hold the clipboard open for a moment. The
                // value expiring late is better than the app falling over.
            }
        }

        onExpiry?.Invoke();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _expiry.Stop();
    }

    /// <summary>
    /// A DWORD zero, which is how the two Windows clipboard formats spell "no".
    /// </summary>
    private static MemoryStream FalseDword() => new([0, 0, 0, 0]);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();
}
