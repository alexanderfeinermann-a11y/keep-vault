using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Windows.Devices.Enumeration;
using Windows.Graphics.Imaging;
using Windows.Media.Capture;
using Windows.Media.Capture.Frames;
using Windows.Media.MediaProperties;
using ZXing;

namespace QrScanner;

// The camera half of the app: opens a capture session, decodes every QR code in
// each frame, and reports only what the arbiter accepts.
//
// Frames are read rather than previewed through a media element. Reading them
// gives what the arbiter needs anyway - every code in the frame, each with its
// own payload and its own position, so two printed codes can be told apart from
// one code seen twice - and the same frames drive the on-screen preview, so the
// user is shown exactly what was decoded rather than a second, separate stream.

public enum ScannerFailureKind
{
    NoCamera,
    CameraUnavailable,
    DecoderUnavailable,
    AccessDenied,
}

public sealed record ScannerFailure(ScannerFailureKind Kind, string Detail = "")
{
    public string Message(Strings strings)
    {
        ArgumentNullException.ThrowIfNull(strings);
        return Kind switch
        {
            ScannerFailureKind.NoCamera => strings.NoCamera,
            ScannerFailureKind.CameraUnavailable => strings.CameraUnavailable,
            ScannerFailureKind.DecoderUnavailable => strings.DecoderUnavailable,
            _ => strings.AccessDenied(Detail.Length == 0 ? strings.StatusUnknown : Detail),
        };
    }
}

public sealed class ScanSession : IAsyncDisposable
{
    /// <summary>
    /// How often a frame is handed to the decoder.
    /// </summary>
    /// <remarks>
    /// The camera delivers 30 frames a second and decoding every one of them
    /// buys nothing: a code held in front of a lens does not change that fast,
    /// and the arbiter's repeat count is measured in frames it actually saw.
    /// Roughly 12 decodes a second keeps a lone code's confirmation under a
    /// second while leaving the machine alone.
    /// </remarks>
    private static readonly TimeSpan DecodeInterval = TimeSpan.FromMilliseconds(80);

    private readonly CodeArbiter _arbiter = new();
    private readonly BarcodeReaderGeneric _reader;
    private readonly SynchronizationContext _uiContext;
    private readonly object _gate = new();

    private MediaCapture? _capture;
    private MediaFrameReader? _frameReader;
    private DateTime _lastDecodeUtc = DateTime.MinValue;
    private bool _paused = true;
    private bool _disposed;

    public ScanSession(SynchronizationContext uiContext)
    {
        _uiContext = uiContext ?? throw new ArgumentNullException(nameof(uiContext));
        _reader = new BarcodeReaderGeneric
        {
            AutoRotate = true,
            Options = new ZXing.Common.DecodingOptions
            {
                // QR only. Every other symbology the library can read is one
                // more way for something that is not a key sheet to produce a
                // payload this app would then offer to copy.
                PossibleFormats = [BarcodeFormat.QR_CODE],
                TryHarder = true,
                TryInverted = true,
            },
        };
    }

    public event Action<ScanOutcome>? Observed;

    public event Action<ScannerFailure>? Failed;

    public event Action<BitmapSource>? PreviewUpdated;

    public async Task StartAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        DeviceInformationCollection cameras;
        try
        {
            cameras = await DeviceInformation.FindAllAsync(DeviceClass.VideoCapture);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
            Report(new ScannerFailure(ScannerFailureKind.NoCamera));
            return;
        }

        if (cameras.Count == 0)
        {
            Report(new ScannerFailure(ScannerFailureKind.NoCamera));
            return;
        }

        var capture = new MediaCapture();
        try
        {
            await capture.InitializeAsync(new MediaCaptureInitializationSettings
            {
                VideoDeviceId = cameras[0].Id,
                StreamingCaptureMode = StreamingCaptureMode.Video,
                MemoryPreference = MediaCaptureMemoryPreference.Cpu,
                SharingMode = MediaCaptureSharingMode.ExclusiveControl,
            });
        }
        catch (UnauthorizedAccessException)
        {
            capture.Dispose();
            Report(new ScannerFailure(ScannerFailureKind.AccessDenied));
            return;
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or ArgumentException)
        {
            capture.Dispose();
            Report(new ScannerFailure(ScannerFailureKind.CameraUnavailable, exception.Message));
            return;
        }

        MediaFrameSource? source = capture.FrameSources.Values
            .FirstOrDefault(candidate => candidate.Info.SourceKind == MediaFrameSourceKind.Color);
        if (source is null)
        {
            capture.Dispose();
            Report(new ScannerFailure(ScannerFailureKind.CameraUnavailable));
            return;
        }

        MediaFrameReader reader;
        try
        {
            reader = await capture.CreateFrameReaderAsync(source, MediaEncodingSubtypes.Bgra8);
            reader.FrameArrived += OnFrameArrived;
            MediaFrameReaderStartStatus status = await reader.StartAsync();
            if (status != MediaFrameReaderStartStatus.Success)
            {
                reader.FrameArrived -= OnFrameArrived;
                reader.Dispose();
                capture.Dispose();
                Report(new ScannerFailure(ScannerFailureKind.CameraUnavailable, status.ToString()));
                return;
            }
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or NotSupportedException)
        {
            capture.Dispose();
            Report(new ScannerFailure(ScannerFailureKind.DecoderUnavailable, exception.Message));
            return;
        }

        lock (_gate)
        {
            _capture = capture;
            _frameReader = reader;
            _paused = false;
        }
    }

    /// <summary>Stops decoding while a result is on screen.</summary>
    public void Suspend()
    {
        lock (_gate)
        {
            _paused = true;
        }
    }

    /// <summary>Resumes decoding and forgets any part-confirmed candidate.</summary>
    public void Resume()
    {
        lock (_gate)
        {
            _arbiter.Reset();
            _lastDecodeUtc = DateTime.MinValue;
            _paused = false;
        }
    }

    private void OnFrameArrived(MediaFrameReader sender, MediaFrameArrivedEventArgs args)
    {
        using MediaFrameReference? reference = sender.TryAcquireLatestFrame();
        SoftwareBitmap? bitmap = reference?.VideoMediaFrame?.SoftwareBitmap;
        if (bitmap is null)
        {
            return;
        }

        lock (_gate)
        {
            if (_paused || _disposed)
            {
                return;
            }

            if (DateTime.UtcNow - _lastDecodeUtc < DecodeInterval)
            {
                return;
            }

            _lastDecodeUtc = DateTime.UtcNow;
        }

        SoftwareBitmap? converted = null;
        try
        {
            SoftwareBitmap usable = bitmap.BitmapPixelFormat == BitmapPixelFormat.Bgra8
                ? bitmap
                : converted = SoftwareBitmap.Convert(bitmap, BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);

            int width = usable.PixelWidth;
            int height = usable.PixelHeight;
            byte[] pixels = new byte[width * height * 4];
            usable.CopyToBuffer(pixels.AsBuffer());

            IReadOnlyList<Detection> detections = Decode(pixels, width, height);
            ScanOutcome outcome;
            lock (_gate)
            {
                if (_paused || _disposed)
                {
                    return;
                }

                outcome = _arbiter.Admit(detections);
            }

            _uiContext.Post(
                _ =>
                {
                    PreviewUpdated?.Invoke(CreatePreview(pixels, width, height));
                    Observed?.Invoke(outcome);
                },
                null);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or ArgumentException)
        {
            Report(new ScannerFailure(ScannerFailureKind.CameraUnavailable, exception.Message));
        }
        finally
        {
            converted?.Dispose();
        }
    }

    /// <summary>
    /// Every QR code in one frame, with its centre in normalised coordinates.
    /// </summary>
    /// <remarks>
    /// The multi-code call is the one that matters: a key sheet carries the same
    /// factor twice, and the whole arbitration rule rests on being told about
    /// both codes separately rather than about whichever one was found first.
    /// </remarks>
    internal IReadOnlyList<Detection> Decode(byte[] bgraPixels, int width, int height)
    {
        ArgumentNullException.ThrowIfNull(bgraPixels);
        var source = new RGBLuminanceSource(bgraPixels, width, height, RGBLuminanceSource.BitmapFormat.BGRA32);
        Result[]? results = _reader.DecodeMultiple(source);
        if (results is null || results.Length == 0)
        {
            return [];
        }

        var detections = new List<Detection>(results.Length);
        foreach (Result result in results)
        {
            string? payload = PayloadInspector.Accept(result.Text);
            if (payload is null)
            {
                continue;
            }

            (double x, double y) = NormalisedCenter(result, width, height);
            detections.Add(new Detection(payload, x, y));
        }

        return detections;
    }

    private static (double X, double Y) NormalisedCenter(Result result, int width, int height)
    {
        ResultPoint[]? points = result.ResultPoints;
        if (points is null || points.Length == 0 || width <= 0 || height <= 0)
        {
            return (0, 0);
        }

        double sumX = 0;
        double sumY = 0;
        foreach (ResultPoint point in points)
        {
            sumX += point.X;
            sumY += point.Y;
        }

        return (sumX / points.Length / width, sumY / points.Length / height);
    }

    private static BitmapSource CreatePreview(byte[] bgraPixels, int width, int height)
    {
        var bitmap = BitmapSource.Create(
            width,
            height,
            96,
            96,
            PixelFormats.Bgra32,
            palette: null,
            bgraPixels,
            width * 4);
        bitmap.Freeze();
        return bitmap;
    }

    private void Report(ScannerFailure failure) => _uiContext.Post(_ => Failed?.Invoke(failure), null);

    public async ValueTask DisposeAsync()
    {
        MediaFrameReader? reader;
        MediaCapture? capture;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _paused = true;
            reader = _frameReader;
            capture = _capture;
            _frameReader = null;
            _capture = null;
        }

        if (reader is not null)
        {
            reader.FrameArrived -= OnFrameArrived;
            try
            {
                await reader.StopAsync();
            }
            catch (Exception exception) when (exception is COMException or InvalidOperationException)
            {
                // Shutting down a camera that has already gone away is not a
                // failure worth reporting to the user.
            }

            reader.Dispose();
        }

        capture?.Dispose();
    }
}
