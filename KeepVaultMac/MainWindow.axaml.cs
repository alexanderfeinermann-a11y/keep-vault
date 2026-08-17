using System.Globalization;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

namespace KalynaArchiver;

public sealed partial class MainWindow : Window, IDisposable
{
    private const int DefaultCompressionLevel = 1;
    private const int MaxCompressionLevel = 5;
    private const int MaxLogCharacters = 1_000_000;
    private const int RetainedLogCharacters = 750_000;
    private const int MaxLogEntryCharacters = 64_000;
    private const string LanguageSettingsFile = "language.txt";
    private const string CipherSuiteSettingsFile = "cipher-suite.txt";
    private const string CompressionSettingsFile = "compression.txt";

    private readonly ZpaqService _zpaq = new();
    private readonly KalynaContainerService _containers = new();
    private readonly IntegrityService _integrity = new();
    private readonly CryptographicEraseService _erase = new();
    private readonly RecoveryService _recovery = new();
    private readonly MacKeySheetService _keySheets = new();
    private readonly IAppSettingsStore _settingsStore;
    private readonly CancellationTokenSource _lifetime = new();

    private GeneratedArchiveEntropy? _generatedEntropy;
    private string? _keySheetFingerprint;
    private string? _extractHint;
    private string? _integrityStatusKey = "integrityChecking";
    private string? _integrityRawMessage;
    private IBrush _integrityBrush = Brush.Parse("#F2BD55");
    private bool _componentsReady;
    private bool _generatedPairReady;
    private bool _extractHintLoaded;
    private bool _extractHintUnavailable;
    private bool _integrityTrusted;
    private bool _suppressExtractTextChanged;
    private bool _disposed;
    private int _operationActive;
    private int _hintLoadVersion;
    private long _lastEntropyUiMinimum = -1;
    private string _language = "de";

    public MainWindow()
        : this(new IsolatedStorageAppSettingsStore())
    {
    }

    internal MainWindow(IAppSettingsStore settingsStore)
    {
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        InitializeComponent();
        LoadLogo();

        _language = LoadLanguage();
        SelectLanguage(_language);
        SelectSuite(LoadSuite());
        CompressionBox.SelectedIndex = LoadCompression();
        EncryptBox.PropertyChanged += EncryptBox_PropertyChanged;
        _componentsReady = true;

        CreatePasswordPanel.Opacity = EncryptBox.IsChecked == true ? 1 : 0.65;
        GeneratedPasswordFirstBox.Text = string.Empty;
        GeneratedPasswordSecondBox.Text = string.Empty;
        ApplyLanguage();
        ResetKeySheetStatus();
        UpdateEntropyStatus(force: true);
        UpdatePasswordPolicyStatus();
        UpdateProtectedOperationControls();

        Opened += MainWindow_Opened;
        Closed += (_, _) => Dispose();
    }

    private EncryptionSuite SelectedEncryptionSuite
    {
        get
        {
            if (CipherSuiteBox.SelectedItem is ComboBoxItem { Tag: string tag }
                && Enum.TryParse(tag, ignoreCase: false, out EncryptionSuite suite))
            {
                return suite;
            }

            return EncryptionSuiteCatalog.Default;
        }
    }

    private async void MainWindow_Opened(object? sender, EventArgs e)
    {
        CaptureText.Text = T("captureUnavailable");
        Log(T("captureBoundaryLog"));
        await CheckIntegrityAsync();
        Log($"ZPAQ: {_zpaq.ResolveExecutable() ?? T("notFound")}");
        if (_integrityTrusted)
        {
            Log(_containers.IsNativeKalynaAvailable
                ? T("kalynaAvailable")
                : $"{T("kalynaMissing")} — {KalynaContainerService.NativeKalynaLoadError ?? T("notFound")}");
            Log(_containers.IsNativeThreefishAvailable
                ? T("threefishAvailable")
                : $"{T("threefishMissing")} — {KalynaContainerService.NativeThreefishLoadError ?? T("notFound")}");
        }
    }

    private void Window_Activated(object? sender, EventArgs e) => UpdatePrivacyShield();

    private void Window_Deactivated(object? sender, EventArgs e) => UpdatePrivacyShield();

    /// <summary>
    /// Conceals secret views while the window is not on screen.
    /// </summary>
    /// <remarks>
    /// The trigger is the window being minimized or hidden, not merely losing
    /// focus. Concealing on deactivation made the app unusable for its own
    /// workflow: dragging files in from the Finder necessarily deactivates the
    /// window, so the shield covered the very drop target the user was aiming
    /// at. A window the user can still see is one they chose to leave open, and
    /// its contents are no more exposed than any other visible window.
    ///
    /// This does not weaken the capture boundary that is already reported in
    /// the security log: macOS offers no enforceable exclusion from screenshots
    /// or screen recording, so the shield was never a capture control to begin
    /// with. It hides secrets from the window preview that macOS renders in
    /// Mission Control and the Dock while the window is put away.
    /// </remarks>
    private void UpdatePrivacyShield()
    {
        PrivacyShield.IsVisible = WindowState == Avalonia.Controls.WindowState.Minimized || !IsVisible;
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        // Minimizing and hiding do not raise Deactivated on their own, so track
        // the properties that actually decide whether the window is on screen.
        if (_componentsReady
            && (change.Property == WindowStateProperty || change.Property == IsVisibleProperty))
        {
            UpdatePrivacyShield();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Interlocked.Increment(ref _hintLoadVersion);
        _lifetime.Cancel();
        ClearCreateSecrets();
        ClearExtractSecrets();
        HintBox.Text = string.Empty;
        _extractHint = null;
        _keySheetFingerprint = null;
        _integrityTrusted = false;
        if (Volatile.Read(ref _operationActive) == 0)
        {
            DisposeStorageAccess();
        }
        UpdateProtectedOperationControls();
        _integrity.Dispose();
        _lifetime.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task CheckIntegrityAsync()
    {
        _integrityTrusted = false;
        UpdateProtectedOperationControls();
        OperationStatusText.Text = T("integrityChecking");
        try
        {
            IntegrityStatus app = await _integrity.CheckSelfAsync(_lifetime.Token);
            IReadOnlyList<ToolIntegrityStatus> tools = await _integrity.CheckNativeToolsAsync(_lifetime.Token);
            foreach (ToolIntegrityStatus component in app.Components)
            {
                Log($"App-Komponente {Path.GetFileName(component.FilePath)}: dual-hash={component.HashMatches}; hybrid={component.HybridSignatureMatches}; Apple={component.SignatureState}");
            }

            foreach (ToolIntegrityStatus tool in tools)
            {
                Log($"Native Komponente {Path.GetFileName(tool.FilePath)}: dual-hash={tool.HashMatches}; hybrid={tool.HybridSignatureMatches}; Apple={tool.SignatureState}");
            }

            _integrityTrusted = app.IsTrusted && tools.Count > 0 && tools.All(tool => tool.IsTrusted);
            _integrityStatusKey = _integrityTrusted ? "integrityOk" : "integrityWarning";
            _integrityRawMessage = null;
            _integrityBrush = Brush.Parse(_integrityTrusted ? "#7EE2B8" : "#F06D7D");
            Log($"SHA3-512(App): {app.ActualSha3_512}");
            Log($"Skein-1024(App): {app.ActualSkein1024}");
            if (!_integrityTrusted)
            {
                Log(T("integrityBlockedLog"));
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            _integrityTrusted = false;
            _integrityStatusKey = "integrityFailed";
            _integrityRawMessage = null;
            _integrityBrush = Brush.Parse("#F06D7D");
            Log(exception.ToString());
        }
        finally
        {
            ApplyIntegrityStatus();
            UpdateProtectedOperationControls();
            OperationStatusText.Text = _integrityTrusted ? T("ready") : T("blocked");
        }
    }

    private void ApplyIntegrityStatus()
    {
        IntegrityText.Text = _integrityRawMessage ?? T(_integrityStatusKey ?? "integrityFailed");
        IntegrityText.Foreground = _integrityBrush;
        IntegrityDot.Fill = _integrityBrush;
    }

    private void Window_PointerMoved(object? sender, PointerEventArgs e)
    {
        if (_disposed || Volatile.Read(ref _operationActive) != 0)
        {
            return;
        }

        var point = e.GetCurrentPoint(this);
        EntropyMixer.AddMouseSample(
            point.Position.X,
            point.Position.Y,
            unchecked((int)e.Timestamp),
            point.Properties.IsLeftButtonPressed,
            point.Properties.IsRightButtonPressed,
            point.Properties.IsMiddleButtonPressed);
        UpdateEntropyStatus(force: false);
    }

    private async void AddFiles_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFile> files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = T("chooseFilesDialog"),
            AllowMultiple = true,
        });
        AddInputStorageItems(files);
        DisposeUnretainedStorageItems(files);
    }

    private async void AddFolder_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = T("chooseFolderDialog"),
            AllowMultiple = false,
        });
        AddInputStorageItems(folders);
        DisposeUnretainedStorageItems(folders);
    }

    private void ClearInputs_Click(object? sender, RoutedEventArgs e)
    {
        InputList.Items.Clear();
        ClearInputStorageAccess();
    }

    private async void ChooseArchive_Click(object? sender, RoutedEventArgs e)
    {
        bool encrypted = EncryptBox.IsChecked == true;
        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = T("saveArchiveDialog"),
            AllowMultiple = false,
            SuggestedStartLocation = _archiveDestinationAccess?.Item as IStorageFolder,
        });
        IStorageFolder? folder = folders.FirstOrDefault();
        foreach (IStorageFolder extra in folders.Skip(1))
        {
            extra.Dispose();
        }

        if (folder is null)
        {
            return;
        }

        if (GetLocalPath(folder) is { } path)
        {
            if (!RetainArchiveDestinationAccess(folder))
            {
                return;
            }

            ArchivePathBox.Text = SuggestTargetArchivePath(path, encrypted);
            ResetKeySheetStatus();
            return;
        }

        folder.Dispose();
    }

    private async void ChooseExtractArchive_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFile> files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = T("chooseArchiveDialog"),
            AllowMultiple = false,
            FileTypeFilter = new[] { AnyArchiveType },
        });
        IStorageFile? file = files.FirstOrDefault();
        foreach (IStorageFile extra in files.Skip(1))
        {
            extra.Dispose();
        }

        if (file is null)
        {
            return;
        }

        if (GetLocalPath(file) is { } path)
        {
            if (!RetainExtractArchiveAccess(file))
            {
                return;
            }

            SetExtractArchivePath(path);
            return;
        }

        file.Dispose();
    }

    private async void ChooseOutputFolder_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = T("chooseOutputDialog"),
            AllowMultiple = false,
        });
        IStorageFolder? folder = folders.FirstOrDefault();
        foreach (IStorageFolder extra in folders.Skip(1))
        {
            extra.Dispose();
        }

        if (folder is null)
        {
            return;
        }

        if (GetLocalPath(folder) is { } path)
        {
            if (!RetainExtractOutputParentAccess(folder))
            {
                return;
            }

            OutputFolderBox.Text = SuggestOutputFolderPath(ExtractArchiveBox.Text ?? string.Empty, path);
            return;
        }

        folder.Dispose();
    }

    private void EncryptBox_PropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.Property == ToggleButton.IsCheckedProperty)
        {
            EncryptBox_Changed();
        }
    }

    private void EncryptBox_Changed()
    {
        if (!_componentsReady)
        {
            return;
        }

        bool enabled = EncryptBox.IsChecked == true;
        CreatePasswordPanel.Opacity = enabled ? 1 : 0.65;
        CreatePasswordPanel.IsEnabled = enabled;
        CipherSuiteBox.IsEnabled = enabled;
        if (!string.IsNullOrWhiteSpace(ArchivePathBox.Text))
        {
            ArchivePathBox.Text = NormalizeTargetArchivePath(ArchivePathBox.Text, enabled);
            ResetKeySheetStatus();
        }
    }

    private void LanguageBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox { SelectedItem: ComboBoxItem { Tag: string language } }
            && language is "de" or "en")
        {
            _language = language;
            if (_componentsReady)
            {
                ApplyLanguage();
                _settingsStore.Write(LanguageSettingsFile, language);
            }
        }
    }

    private void CipherSuiteBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_componentsReady)
        {
            return;
        }

        ResetKeySheetStatus();
        _settingsStore.Write(CipherSuiteSettingsFile, SelectedEncryptionSuite.ToString());
        Log(string.Format(CultureInfo.CurrentCulture, T("cipherSuiteSelected"), EncryptionSuiteCatalog.Get(SelectedEncryptionSuite).DisplayName));
    }

    private void CompressionBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_componentsReady && CompressionBox.SelectedIndex is >= 0 and <= MaxCompressionLevel)
        {
            _settingsStore.Write(CompressionSettingsFile, CompressionBox.SelectedIndex.ToString(CultureInfo.InvariantCulture));
        }
    }

    private void ArchivePathBox_TextChanged(object? sender, TextChangedEventArgs e)
    {
        ResetKeySheetStatus();
        ReleaseArchiveDestinationAccessIfMismatched(ArchivePathBox.Text ?? string.Empty);
    }

    private void OutputFolderBox_TextChanged(object? sender, TextChangedEventArgs e) =>
        ReleaseExtractOutputAccessIfMismatched(OutputFolderBox.Text ?? string.Empty);

    private void CreatePasswordBox_TextChanged(object? sender, TextChangedEventArgs e) => UpdatePasswordPolicyStatus();

    private async void CreateArchive_Click(object? sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            await ShowBlockedAsync();
            return;
        }

        string? createdArchive = null;
        GeneratedArchiveEntropy? prepared = null;
        try
        {
            string[] inputs = InputList.Items.OfType<string>().ToArray();
            if (inputs.Length == 0)
            {
                await WarnAsync(T("inputsMissing"));
                return;
            }

            bool encrypted = EncryptBox.IsChecked == true;
            string archivePath = NormalizeTargetArchivePath(ArchivePathBox.Text?.Trim() ?? string.Empty, encrypted);
            if (archivePath.Length == 0)
            {
                await WarnAsync(T("targetMissing"));
                return;
            }

            ArchivePathBox.Text = archivePath;
            if (!await EnsureArchiveDestinationAccessAsync(archivePath))
            {
                return;
            }

            EnsureArchiveTargetIsSafe(archivePath, inputs);
            if (encrypted)
            {
                EnsureCreationFactors();
                EnsureKeySheetHandled(archivePath);
                if (!_containers.IsNativeSuiteAvailable(SelectedEncryptionSuite))
                {
                    throw new InvalidOperationException(string.Format(
                        CultureInfo.CurrentCulture,
                        T("selectedSuiteMissing"),
                        EncryptionSuiteCatalog.Get(SelectedEncryptionSuite).DisplayName));
                }

                prepared = _generatedEntropy is { HasPendingEncryptionParameters: true } entropy ? entropy : null;
                if (prepared is null)
                {
                    EnsureEntropyReady(EntropyPurpose.Salt);
                    EnsureEntropyReady(EntropyPurpose.NonceFirst);
                    EnsureEntropyReady(EntropyPurpose.NonceSecond);
                    EnsureEntropyReady(EntropyPurpose.NonceThird);
                }
            }

            int compression = CompressionBox.SelectedIndex is >= 0 and <= MaxCompressionLevel
                ? CompressionBox.SelectedIndex
                : DefaultCompressionLevel;
            OperationStatusText.Text = T("working");
            Log(T("creatingZpaq"));
            ProcessResult result;
            if (encrypted)
            {
                EncryptionSuite suite = SelectedEncryptionSuite;
                Log(string.Format(CultureInfo.CurrentCulture, T("encryptingStreaming"), EncryptionSuiteCatalog.Get(suite).DisplayName));
                async Task ConsumeAsync(Stream zpaqStream, CancellationToken cancellationToken)
                {
                    if (prepared is null)
                    {
                        await _containers.EncryptZpaqStreamAsync(
                            zpaqStream,
                            archivePath,
                            CreatePasswordBox.Text ?? string.Empty,
                            GeneratedPasswordFirstBox.Text ?? string.Empty,
                            GeneratedPasswordSecondBox.Text ?? string.Empty,
                            suite,
                            HintBox.Text?.Trim(),
                            Progress(),
                            cancellationToken);
                    }
                    else
                    {
                        await _containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                            zpaqStream,
                            archivePath,
                            CreatePasswordBox.Text ?? string.Empty,
                            GeneratedPasswordFirstBox.Text ?? string.Empty,
                            GeneratedPasswordSecondBox.Text ?? string.Empty,
                            suite,
                            prepared,
                            HintBox.Text?.Trim(),
                            Progress(),
                            cancellationToken);
                    }

                    createdArchive = archivePath;
                }

                result = await _zpaq.AddStreamingAsync(inputs, compression, ConsumeAsync, Progress(), _lifetime.Token);
            }
            else
            {
                result = await _zpaq.AddAsync(archivePath, inputs, compression, Progress(), _lifetime.Token);
                if (result.Succeeded)
                {
                    createdArchive = archivePath;
                }
            }

            if (!result.Succeeded)
            {
                Log(result.StandardError);
                if (createdArchive is not null)
                {
                    CleanupFailedArchive(createdArchive);
                    createdArchive = null;
                }

                await ErrorAsync(T("zpaqCreateFailed"));
                return;
            }

            if (encrypted)
            {
                await _recovery.CreateAuthenticatedAsync(
                    archivePath,
                    CreatePasswordBox.Text ?? string.Empty,
                    GeneratedPasswordFirstBox.Text ?? string.Empty,
                    GeneratedPasswordSecondBox.Text ?? string.Empty,
                    Progress(),
                    _lifetime.Token);
            }
            else
            {
                await _recovery.CreateAsync(archivePath, Progress(), _lifetime.Token);
            }

            // Deleting the originals is gated on proving the archive reproduces
            // them, so it happens before the secrets are cleared: an encrypted
            // archive can only be read back with the factors still in hand.
            bool deleteOriginals = DeleteOriginalsBox.IsChecked == true;
            bool originalsDeleted = false;
            if (deleteOriginals)
            {
                originalsDeleted = await VerifyAndDeleteOriginalsAsync(archivePath, inputs, encrypted);
            }

            createdArchive = null;
            ClearCreateSecrets();
            Log($"{T("done")}: {archivePath}");
            await InfoAsync(deleteOriginals && originalsDeleted
                ? T("archiveCreatedOriginalsDeleted")
                : T("archiveCreated"));
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            if (createdArchive is not null)
            {
                TryCleanupFailedArchive(createdArchive);
            }

            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void ExtractArchive_Click(object? sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            await ShowBlockedAsync();
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text?.Trim() ?? string.Empty;
            string output = OutputFolderBox.Text?.Trim() ?? string.Empty;
            if (archive.Length > 0 && output.Length == 0)
            {
                string? retainedParent = _extractOutputParentAccess is null
                    ? null
                    : GetLocalPath(_extractOutputParentAccess.Item);
                output = retainedParent is null
                    ? SuggestOutputFolderPath(archive)
                    : SuggestOutputFolderPath(archive, retainedParent);
                OutputFolderBox.Text = output;
            }

            if (archive.Length == 0 || output.Length == 0)
            {
                await WarnAsync(T("extractInputMissing"));
                return;
            }

            if (!await EnsureExtractArchiveParentAccessAsync(archive)
                || !await EnsureExtractOutputParentAccessAsync(output))
            {
                return;
            }

            if (!File.Exists(archive))
            {
                await WarnAsync(T("archiveMissing"));
                return;
            }

            archive = await PrepareArchiveForUseAsync(archive);
            bool encrypted = await _containers.LooksEncryptedAsync(archive, _lifetime.Token);
            ProcessResult result;
            if (encrypted)
            {
                (KalynaContainerInfo info, string effective) = await ReadContainerInfoWithRecoveryAsync(archive);
                archive = effective;
                SetExtractArchivePathWithoutHint(archive);
                SetExtractHint(info.Hint, loaded: true);
                EnsureExtractionFactors();
                Log($"Cipher suite: {info.Algorithm}");
                Log(T("extractingStreaming"));
                result = await ExecuteEncryptedWithRecoveryRetryAsync(
                    archive,
                    effectivePath => _zpaq.ExtractStreamingAsync(
                        (zpaqInput, token) => _containers.DecryptToStreamAsync(
                            effectivePath,
                            ExtractPasswordBox.Text ?? string.Empty,
                            ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                            ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                            zpaqInput,
                            Progress(),
                            token),
                        output,
                        Progress(),
                        _lifetime.Token));
            }
            else
            {
                Log(T("extracting"));
                result = await _zpaq.ExtractAsync(archive, output, Progress(), _lifetime.Token);
            }

            if (!result.Succeeded)
            {
                Log(result.StandardError);
                await ErrorAsync(T("zpaqExtractFailed"));
                return;
            }

            ClearExtractSecrets();
            Log($"{T("extractedTo")}: {output}");
            await InfoAsync(T("archiveExtracted"));
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void ListArchive_Click(object? sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            await ShowBlockedAsync();
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text?.Trim() ?? string.Empty;
            if (archive.Length == 0)
            {
                await WarnAsync(T("archiveMissing"));
                return;
            }

            if (!await EnsureExtractArchiveParentAccessAsync(archive))
            {
                return;
            }

            if (!File.Exists(archive))
            {
                await WarnAsync(T("archiveMissing"));
                return;
            }

            archive = await PrepareArchiveForUseAsync(archive);
            bool encrypted = await _containers.LooksEncryptedAsync(archive, _lifetime.Token);
            ProcessResult result;
            if (encrypted)
            {
                (KalynaContainerInfo info, string effective) = await ReadContainerInfoWithRecoveryAsync(archive);
                archive = effective;
                SetExtractArchivePathWithoutHint(archive);
                SetExtractHint(info.Hint, loaded: true);
                EnsureExtractionFactors();
                result = await ExecuteEncryptedWithRecoveryRetryAsync(
                    archive,
                    effectivePath => _zpaq.ListStreamingAsync(
                        (zpaqInput, token) => _containers.DecryptToStreamAsync(
                            effectivePath,
                            ExtractPasswordBox.Text ?? string.Empty,
                            ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                            ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                            zpaqInput,
                            Progress(),
                            token),
                        Progress(),
                        _lifetime.Token));
            }
            else
            {
                result = await _zpaq.ListAsync(archive, Progress(), _lifetime.Token);
            }

            Log(result.StandardOutput);
            Log(result.StandardError);
            if (result.Succeeded)
            {
                ClearExtractSecrets();
            }
            else
            {
                await ErrorAsync(T("zpaqListFailed"));
            }
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void EmergencyRecovery_Click(object? sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            await ShowBlockedAsync();
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text?.Trim() ?? string.Empty;
            if (archive.Length == 0)
            {
                await WarnAsync(T("archiveMissing"));
                return;
            }

            if (!await EnsureExtractArchiveParentAccessAsync(archive))
            {
                return;
            }

            if (!File.Exists(archive))
            {
                await WarnAsync(T("archiveMissing"));
                return;
            }

            RecoveryProtectionMode? mode = await _recovery.TryReadProtectionModeAsync(archive, _lifetime.Token);
            if (mode is null)
            {
                await WarnAsync(T("emergencyRecoveryMissing"));
                return;
            }

            bool confirmed = await ConfirmAsync(mode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                ? T("emergencyEncryptedWarning")
                : T("emergencyPlainWarning"));
            if (!confirmed)
            {
                return;
            }

            RecoveryRepairResult result;
            if (mode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
            {
                EnsureExtractionFactors();
                result = await _recovery.RecoverToNewFileAuthenticatedAsync(
                    archive,
                    ExtractPasswordBox.Text ?? string.Empty,
                    ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                    ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                    Progress(),
                    _lifetime.Token);
            }
            else
            {
                result = await _recovery.RecoverToNewFileAsync(archive, Progress(), _lifetime.Token);
            }

            string effective = result.OutputPath ?? archive;
            SetExtractArchivePath(effective);
            Log(result.Message);
            Log(string.Format(CultureInfo.CurrentCulture, T("recoveryNewFile"), effective));
            await InfoAsync(result.Message);
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private void GeneratePassword_Click(object? sender, RoutedEventArgs e)
    {
        if (Volatile.Read(ref _operationActive) != 0)
        {
            return;
        }

        try
        {
            EncryptBox.IsChecked = true;
            foreach (EntropyPurpose purpose in Enum.GetValues<EntropyPurpose>())
            {
                EnsureEntropyReady(purpose);
            }

            GeneratedArchiveEntropy next = EntropyMixer.CreateArchiveEntropy();
            GeneratedArchiveEntropy? previous = _generatedEntropy;
            _generatedEntropy = next;
            _generatedPairReady = true;
            GeneratedPasswordFirstBox.Text = next.FirstPassword;
            GeneratedPasswordSecondBox.Text = next.SecondPassword;
            previous?.Dispose();
            ResetKeySheetStatus();
            UpdateEntropyStatus(force: true);
            UpdatePasswordPolicyStatus();
            Log(T("generatedPasswordLog"));
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            _ = ErrorAsync(exception.Message);
        }
    }

    private async void SaveKeySheet_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            string archivePath = NormalizeTargetArchivePath(ArchivePathBox.Text?.Trim() ?? string.Empty, encrypted: true);
            if (archivePath.Length == 0)
            {
                await WarnAsync(T("targetMissing"));
                return;
            }

            ArchivePathBox.Text = archivePath;
            if (!await EnsureArchiveDestinationAccessAsync(archivePath))
            {
                return;
            }

            MacKeySheetData data = BuildKeySheetData();
            using IStorageFile? file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = T("saveTestKeySheetDialog"),
                DefaultExtension = "pdf",
                SuggestedFileName = $"{Path.GetFileNameWithoutExtension(data.ArchivePath)}-key-sheets-test-export.pdf",
                FileTypeChoices = new[] { PdfType },
            });
            if (file?.TryGetLocalPath() is not { } path)
            {
                return;
            }

            if (_disposed)
            {
                return;
            }

            using MacSecurityScopedResourceLease fileAccess = MacSecurityScopedResourceLease.Acquire(file);

            bool confirmed = await ConfirmAsync(T("testPdfWarning"));
            if (!confirmed)
            {
                return;
            }

            // Two files, one per factor: exporting both into a single document
            // would put the whole key in one object, which is exactly what the
            // separated sheets exist to prevent.
            string directory = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory;
            string stem = Path.GetFileNameWithoutExtension(path);
            string firstPath = Path.Combine(directory, $"{stem}-Faktor-A.pdf");
            string secondPath = Path.Combine(directory, $"{stem}-Faktor-B.pdf");
            _keySheets.SaveExplicitTestPdf(data, firstPath, secondPath);
            MarkKeySheetHandled(data);
            Log(string.Format(CultureInfo.CurrentCulture, T("keySheetTestPdfSavedLog"), firstPath));
            Log(string.Format(CultureInfo.CurrentCulture, T("keySheetTestPdfSavedLog"), secondPath));
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
    }

    private async void PrintKeySheet_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            string archivePath = NormalizeTargetArchivePath(ArchivePathBox.Text?.Trim() ?? string.Empty, encrypted: true);
            if (archivePath.Length == 0)
            {
                await WarnAsync(T("targetMissing"));
                return;
            }

            ArchivePathBox.Text = archivePath;
            if (!await EnsureArchiveDestinationAccessAsync(archivePath))
            {
                return;
            }

            MacKeySheetData data = BuildKeySheetData();
            IReadOnlyList<string> printers = await _keySheets.GetPhysicalPrintersAsync(_lifetime.Token);
            if (printers.Count == 0)
            {
                throw new InvalidOperationException(T("noPhysicalPrinter"));
            }

            string? selected = printers.Count == 1
                ? printers[0]
                : await PrinterSelectionDialog.ShowAsync(this, T("selectPrinter"), printers, T("print"), T("cancel"));
            if (selected is null)
            {
                return;
            }

            await _keySheets.PrintAsync(data, selected, _lifetime.Token);
            MarkKeySheetHandled(data);
            Log(string.Format(CultureInfo.CurrentCulture, T("keySheetPrintedLog"), selected));
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
    }

    private void ClearCreateSecrets_Click(object? sender, RoutedEventArgs e) => ClearCreateSecrets();

    private void ClearExtractSecrets_Click(object? sender, RoutedEventArgs e) => ClearExtractSecrets();

    /// <summary>
    /// Extracts the finished archive again, compares it byte for byte with the
    /// inputs, and only then deletes the originals.
    /// </summary>
    /// <remarks>
    /// The order is the whole point. A compression or encryption fault, a
    /// truncated write or a silently dropped input would all still report a
    /// successful archive, and for this kind of tool the loss would surface
    /// only years later when the archive is finally needed. So the archive that
    /// was actually written is read back, and anything short of a complete
    /// match leaves every original in place.
    ///
    /// The extraction goes to a private directory that is removed afterwards,
    /// so the round trip never leaves a second plaintext copy behind.
    /// </remarks>
    private async Task<bool> VerifyAndDeleteOriginalsAsync(string archivePath, string[] inputs, bool encrypted)
    {
        // The temporary directory sits below /var/folders, and /var is itself a
        // symlink to /private/var. Every read here goes through the
        // symlink-refusing open, which rejects a symlink anywhere in the path,
        // so the real path has to be resolved before the directory is used.
        string verifyRoot = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-verify-").FullName);
        try
        {
            File.SetUnixFileMode(
                verifyRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Log(T("verifyingBeforeDelete"));
            OperationStatusText.Text = T("verifyingBeforeDelete");

            // Pin which archive this verification is about, before a single byte
            // of it is read back. Deleting the originals is the one step here
            // that cannot be undone, so it must be tied to the file that was
            // actually proven good, not merely to the path it sat at.
            MacOriginalDeletionService.ArchiveIdentity verifiedArchive =
                MacOriginalDeletionService.CaptureArchiveIdentity(archivePath);

            ProcessResult extraction = encrypted
                ? await ExtractEncryptedForVerificationAsync(archivePath, verifyRoot)
                : await _zpaq.ExtractAsync(archivePath, verifyRoot, Progress(), _lifetime.Token);
            if (!extraction.Succeeded)
            {
                Log(extraction.StandardError);
                await ErrorAsync(T("verifyExtractFailed"));
                return false;
            }

            MacOriginalDeletionService.VerificationResult verification =
                await MacOriginalDeletionService.VerifyExtractionAsync(
                    inputs,
                    verifyRoot,
                    Progress(),
                    _lifetime.Token);
            if (!verification.Verified)
            {
                Log($"{T("verifyMismatch")} — {verification.Failure}");
                await ErrorAsync(T("verifyMismatch"));
                return false;
            }

            Log(string.Format(
                CultureInfo.CurrentCulture,
                T("verifyMatched"),
                verification.FilesCompared,
                verification.BytesCompared));

            IReadOnlyList<string> failures = MacOriginalDeletionService.DeleteOriginals(
                inputs,
                archivePath,
                verifiedArchive);
            if (failures.Count > 0)
            {
                Log($"{T("deleteOriginalsFailed")} — {string.Join("; ", failures)}");
                await ErrorAsync(T("deleteOriginalsFailed"));
                return false;
            }

            InputList.Items.Clear();
            ClearInputStorageAccess();
            Log(T("originalsDeleted"));
            return true;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or InvalidOperationException)
        {
            // The archive itself was written and is fine; only the read-back
            // failed. Report that and keep both the archive and every original,
            // rather than letting the outer handler discard a good archive.
            Log($"{T("verifyMismatch")} — {exception.Message}");
            await ErrorAsync(T("verifyMismatch"));
            return false;
        }
        finally
        {
            // The extracted copy is plaintext regardless of how the archive was
            // encrypted, so it is removed whether the comparison succeeded or
            // not.
            try
            {
                Directory.Delete(verifyRoot, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Log($"{T("verifyCleanupFailed")} — {verifyRoot}");
            }
        }
    }

    private async Task<ProcessResult> ExtractEncryptedForVerificationAsync(string archivePath, string outputRoot)
    {
        return await _zpaq.ExtractStreamingAsync(
            (zpaqStream, cancellationToken) => _containers.DecryptToStreamAsync(
                archivePath,
                CreatePasswordBox.Text ?? string.Empty,
                GeneratedPasswordFirstBox.Text ?? string.Empty,
                GeneratedPasswordSecondBox.Text ?? string.Empty,
                zpaqStream,
                Progress(),
                cancellationToken),
            outputRoot,
            Progress(),
            _lifetime.Token);
    }

    private async void ChooseEraseFile_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFile> files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = T("chooseEraseDialog"),
            AllowMultiple = false,
            FileTypeFilter = new[] { EncryptedArchiveType },
        });
        IStorageFile? file = files.FirstOrDefault();
        foreach (IStorageFile extra in files.Skip(1))
        {
            extra.Dispose();
        }

        if (file is null)
        {
            return;
        }

        if (GetLocalPath(file) is { } path)
        {
            if (!RetainEraseArchiveAccess(file))
            {
                return;
            }

            SetErasePath(path);
            return;
        }

        file.Dispose();
    }

    private async void AnalyzeErase_Click(object? sender, RoutedEventArgs e) => await AnalyzeEraseAsync();

    private void ErasePathBox_TextChanged(object? sender, TextChangedEventArgs e)
    {
        if (_componentsReady)
        {
            EraseConfirmBox.IsChecked = false;
            EraseStatusText.Text = T("eraseNotAnalyzed");
            ReleaseEraseAccessIfMismatched(ErasePathBox.Text ?? string.Empty);
        }
    }

    private async void EraseContainer_Click(object? sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            await ShowBlockedAsync();
            return;
        }

        try
        {
            string path = ErasePathBox.Text?.Trim() ?? string.Empty;
            if (path.Length == 0)
            {
                await WarnAsync(T("eraseMissing"));
                return;
            }

            if (EraseConfirmBox.IsChecked != true)
            {
                await WarnAsync(T("eraseConfirmMissing"));
                return;
            }

            if (!await EnsureEraseArchiveParentAccessAsync(path))
            {
                return;
            }

            using MacSecurityScopedResourceLease operationAccess = AcquireTransientEraseAccess(path);
            if (!File.Exists(path))
            {
                await WarnAsync(T("eraseMissing"));
                return;
            }

            CryptoEraseAnalysis analysis = await _erase.AnalyzeAsync(path, _lifetime.Token);
            EraseStatusText.Text = analysis.Message;
            EraseHardwareNoticeText.Text = analysis.HardwareNotice;
            if (!analysis.IsEncryptedContainer)
            {
                await WarnAsync(analysis.Message);
                return;
            }

            if (!await ConfirmAsync(T("eraseFinalConfirm")))
            {
                return;
            }

            CryptoEraseResult result = await _erase.EraseEncryptedContainerAsync(path, Progress(), _lifetime.Token);
            EraseStatusText.Text = result.Message;
            ErasePathBox.Text = string.Empty;
            EraseConfirmBox.IsChecked = false;
            Log(result.Message);
            await InfoAsync(result.Message);
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async Task AnalyzeEraseAsync()
    {
        try
        {
            string path = ErasePathBox.Text?.Trim() ?? string.Empty;
            if (path.Length == 0)
            {
                await WarnAsync(T("eraseMissing"));
                return;
            }

            if (!await EnsureEraseArchiveParentAccessAsync(path))
            {
                return;
            }

            using MacSecurityScopedResourceLease operationAccess = AcquireTransientEraseAccess(path);
            if (!File.Exists(path))
            {
                await WarnAsync(T("eraseMissing"));
                return;
            }

            CryptoEraseAnalysis analysis = await _erase.AnalyzeAsync(path, _lifetime.Token);
            EraseStatusText.Text = analysis.Message;
            EraseHardwareNoticeText.Text = analysis.HardwareNotice;
            Log(analysis.Message);
            Log(analysis.HardwareNotice);
        }
        catch (Exception exception)
        {
            Log(exception.ToString());
            await ErrorAsync(exception.Message);
        }
    }

    private void ClearLog_Click(object? sender, RoutedEventArgs e) => LogBox.Text = string.Empty;

    private void ClearCreateSecrets()
    {
        GeneratedArchiveEntropy? entropy = _generatedEntropy;
        _generatedEntropy = null;
        _generatedPairReady = false;
        CreatePasswordBox.Text = string.Empty;
        CreatePasswordConfirmBox.Text = string.Empty;
        GeneratedPasswordFirstBox.Text = string.Empty;
        GeneratedPasswordSecondBox.Text = string.Empty;
        entropy?.Dispose();
        ResetKeySheetStatus();
        UpdateEntropyStatus(force: true);
        UpdatePasswordPolicyStatus();
    }

    private void ClearExtractSecrets()
    {
        ExtractPasswordBox.Text = string.Empty;
        ExtractGeneratedPasswordFirstBox.Text = string.Empty;
        ExtractGeneratedPasswordSecondBox.Text = string.Empty;
    }

    private void EnsureCreationFactors()
    {
        string first = GeneratedPasswordFirstBox.Text ?? string.Empty;
        string second = GeneratedPasswordSecondBox.Text ?? string.Empty;
        EnsureGeneratedPassword(first);
        EnsureGeneratedPassword(second);
        PasswordKeyService.ValidateUserPasswordForCreation(CreatePasswordBox.Text ?? string.Empty, first, second);
        if (!string.Equals(CreatePasswordBox.Text, CreatePasswordConfirmBox.Text, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("passwordMismatch"));
        }
    }

    private void EnsureExtractionFactors()
    {
        string password = ExtractPasswordBox.Text ?? string.Empty;
        if (password.Length < PasswordKeyService.MinPasswordLength || password.Length > PasswordKeyService.MaxPasswordLength)
        {
            throw new InvalidOperationException(T("passwordLength"));
        }

        EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text ?? string.Empty);
        EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text ?? string.Empty);
    }

    private static void EnsureGeneratedPassword(string value) => _ = PasswordKeyService.NormalizeGeneratedPassword(value);

    private void EnsureEntropyReady(EntropyPurpose purpose)
    {
        if (EntropyMixer.HasRequiredSamples(purpose))
        {
            return;
        }

        throw new InvalidOperationException(string.Format(
            CultureInfo.CurrentCulture,
            T("entropyNotReady"),
            EntropyMixer.RequiredMouseSamplesPerPurpose,
            EntropyMixer.GetSampleCount(purpose),
            EntropyMixer.MissingSamples(purpose)));
    }

    private void UpdateEntropyStatus(bool force)
    {
        if (!_componentsReady)
        {
            return;
        }

        EntropyPoolStatus status = EntropyMixer.GetPoolStatus();

        // 512 samples per pool is the minimum that unlocks generation, not a
        // ceiling: collection continues for as long as the pointer moves, and
        // the reported counts must keep rising so that the extra entropy stays
        // visible. Throttle on the true pool minimum, never on the value
        // clamped for the progress bar — clamping the throttle input froze the
        // whole display at 512.
        long poolMinimum = status.Minimum;
        if (!force && poolMinimum == _lastEntropyUiMinimum)
        {
            return;
        }

        _lastEntropyUiMinimum = poolMinimum;
        EntropyProgress.Value = Math.Min(poolMinimum, EntropyMixer.RequiredMouseSamplesPerPurpose);
        bool ready = poolMinimum >= EntropyMixer.RequiredMouseSamplesPerPurpose;
        GeneratePasswordButton.IsEnabled = ready && Volatile.Read(ref _operationActive) == 0;
        GeneratePasswordButton.Content = T(_generatedPairReady ? "regeneratePassword" : "generatePassword");
        string key = !_generatedPairReady
            ? "entropyCollecting"
            : _generatedEntropy is { HasPendingEncryptionParameters: true }
                ? "entropyPrepared"
                : "entropyRetry";
        EntropyStatusText.Text = string.Format(
            CultureInfo.CurrentCulture,
            T(key),
            status.Total,
            status.GeneratedPasswordFirst,
            status.GeneratedPasswordSecond,
            status.Salt,
            status.NonceFirst,
            status.NonceSecond,
            status.NonceThird,
            EntropyMixer.RequiredMouseSamplesPerPurpose);
        EntropyStatusText.Foreground = Brush.Parse(key == "entropyPrepared" ? "#7EE2B8" : key == "entropyRetry" ? "#F2BD55" : "#5DE4EC");
    }

    private void UpdatePasswordPolicyStatus()
    {
        if (!_componentsReady)
        {
            return;
        }

        PasswordPolicyAnalysis analysis = PasswordKeyService.AnalyzeUserPassword(
            CreatePasswordBox.Text ?? string.Empty,
            GeneratedPasswordFirstBox.Text ?? string.Empty,
            GeneratedPasswordSecondBox.Text ?? string.Empty);
        PasswordEntropyStatusText.Text = string.Format(
            CultureInfo.InvariantCulture,
            T("passwordEntropy"),
            analysis.ConservativeEntropyBits,
            PasswordKeyService.MinimumConservativeEntropyBits);
        PasswordEntropyStatusText.Foreground = Brush.Parse(
            analysis.ConservativeEntropyBits >= PasswordKeyService.MinimumConservativeEntropyBits ? "#7EE2B8" : "#F2BD55");
        PasswordPolicyStatusText.Text = analysis.IsAccepted
            ? T("passwordAccepted")
            : string.Join(Environment.NewLine, analysis.Violations.Select(PasswordViolationText));
        PasswordPolicyStatusText.Foreground = Brush.Parse(analysis.IsAccepted ? "#7EE2B8" : "#F29AA6");
    }

    private string PasswordViolationText(PasswordPolicyViolation violation) => violation switch
    {
        PasswordPolicyViolation.TooShort => string.Format(CultureInfo.CurrentCulture, T("passwordTooShort"), PasswordKeyService.MinPasswordLength),
        PasswordPolicyViolation.TooLong => string.Format(CultureInfo.CurrentCulture, T("passwordTooLong"), PasswordKeyService.MaxPasswordLength),
        PasswordPolicyViolation.ControlCharacter => T("passwordControl"),
        PasswordPolicyViolation.InvalidUnicode => T("passwordUnicode"),
        PasswordPolicyViolation.NotEnoughCharacterClasses => T("passwordClasses"),
        PasswordPolicyViolation.NotEnoughDistinctCharacters => T("passwordDistinct"),
        PasswordPolicyViolation.NotEnoughNonHexCharacters => T("passwordNonHex"),
        PasswordPolicyViolation.HexadecimalRunTooLong => T("passwordHexRun"),
        PasswordPolicyViolation.MatchesGeneratedPassword => T("passwordMatchesFactor"),
        PasswordPolicyViolation.InsufficientConservativeEntropy => T("passwordLowEntropy"),
        _ => T("passwordInvalid"),
    };

    private MacKeySheetData BuildKeySheetData()
    {
        EnsureGeneratedPassword(GeneratedPasswordFirstBox.Text ?? string.Empty);
        EnsureGeneratedPassword(GeneratedPasswordSecondBox.Text ?? string.Empty);
        string archive = NormalizeTargetArchivePath(ArchivePathBox.Text?.Trim() ?? string.Empty, encrypted: true);
        if (archive.Length == 0)
        {
            throw new InvalidOperationException(T("targetMissing"));
        }

        ArchivePathBox.Text = archive;
        EncryptBox.IsChecked = true;
        return new MacKeySheetData(
            Path.GetFullPath(archive),
            SelectedEncryptionSuite,
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordFirstBox.Text ?? string.Empty),
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordSecondBox.Text ?? string.Empty),
            DateTime.Now,
            IsEnglish,
            string.Empty);
    }

    private void ResetKeySheetStatus()
    {
        _keySheetFingerprint = null;
        if (_componentsReady)
        {
            KeySheetStatusText.Text = T("keySheetMissing");
            KeySheetStatusText.Foreground = Brush.Parse("#F2BD55");
        }
    }

    private void MarkKeySheetHandled(MacKeySheetData data)
    {
        _keySheetFingerprint = BuildKeySheetFingerprint(data);
        KeySheetStatusText.Text = T("keySheetHandled");
        KeySheetStatusText.Foreground = Brush.Parse("#7EE2B8");
    }

    private void EnsureKeySheetHandled(string archivePath)
    {
        var current = new MacKeySheetData(
            Path.GetFullPath(archivePath),
            SelectedEncryptionSuite,
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordFirstBox.Text ?? string.Empty),
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordSecondBox.Text ?? string.Empty),
            DateTime.MinValue);
        if (!string.Equals(_keySheetFingerprint, BuildKeySheetFingerprint(current), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("keySheetRequired"));
        }
    }

    /// <summary>
    /// Puts the Keep Vault mark into the window header and the privacy shield.
    /// </summary>
    /// <remarks>
    /// Loaded from an embedded resource rather than through Avalonia's resource
    /// URIs: the assembly is named "Keep Vault", and the space in that name does
    /// not survive an avares:// URI. A missing logo is not worth refusing to
    /// start over, so a failure here leaves the image empty and the app usable.
    /// </remarks>
    private void LoadLogo()
    {
        try
        {
            using Stream? stream = typeof(MainWindow).Assembly
                .GetManifestResourceStream("KeepVault.Logo.png");
            if (stream is null)
            {
                return;
            }

            var logo = new Bitmap(stream);
            HeaderLogoImage.Source = logo;
            PrivacyShieldLogoImage.Source = logo;
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
        }
    }

    private static string BuildKeySheetFingerprint(MacKeySheetData data)
    {
        return MacKeySheetService.BuildBindingFingerprint(data);
    }

    private async Task<string> PrepareArchiveForUseAsync(string archive)
    {
        if (await _containers.LooksEncryptedAsync(archive, _lifetime.Token))
        {
            return archive;
        }

        RecoveryProtectionMode? mode = await _recovery.TryReadProtectionModeAsync(archive, _lifetime.Token);
        if (mode is null)
        {
            if (HasEncryptedArchiveExtension(archive))
            {
                throw new InvalidDataException(T("encryptedHeaderWithoutRecovery"));
            }

            return archive;
        }

        RecoveryRepairResult repair;
        if (mode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
        {
            EnsureExtractionFactors();
            repair = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Text ?? string.Empty,
                ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                Progress(),
                _lifetime.Token);
        }
        else
        {
            repair = await _recovery.VerifyAndRepairAsync(archive, Progress(), _lifetime.Token);
        }

        string effective = repair.OutputPath ?? archive;
        if (!string.Equals(effective, archive, StringComparison.Ordinal))
        {
            SetExtractArchivePathWithoutHint(effective);
            Log(string.Format(CultureInfo.CurrentCulture, T("recoveryNewFile"), effective));
        }

        return effective;
    }

    private async Task<(KalynaContainerInfo Info, string Archive)> ReadContainerInfoWithRecoveryAsync(string archive)
    {
        try
        {
            return (await _containers.ReadContainerInfoAsync(archive, _lifetime.Token), archive);
        }
        catch (Exception exception) when (exception is InvalidDataException or EndOfStreamException)
        {
            EnsureExtractionFactors();
            RecoveryRepairResult repair = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Text ?? string.Empty,
                ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                Progress(),
                _lifetime.Token);
            if (!repair.Repaired)
            {
                throw;
            }

            string effective = repair.OutputPath ?? archive;
            Log(string.Format(CultureInfo.CurrentCulture, T("recoveryNewFile"), effective));
            return (await _containers.ReadContainerInfoAsync(effective, _lifetime.Token), effective);
        }
    }

    private async Task<ProcessResult> ExecuteEncryptedWithRecoveryRetryAsync(
        string archive,
        Func<string, Task<ProcessResult>> operation)
    {
        try
        {
            return await operation(archive);
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidDataException or EndOfStreamException)
        {
            RecoveryRepairResult repair = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Text ?? string.Empty,
                ExtractGeneratedPasswordFirstBox.Text ?? string.Empty,
                ExtractGeneratedPasswordSecondBox.Text ?? string.Empty,
                Progress(),
                _lifetime.Token);
            if (!repair.Repaired)
            {
                throw;
            }

            string effective = repair.OutputPath ?? archive;
            SetExtractArchivePathWithoutHint(effective);
            Log(string.Format(CultureInfo.CurrentCulture, T("recoveryNewFile"), effective));
            Log(T("retryAfterRecovery"));
            return await operation(effective);
        }
    }

    private void ExtractArchiveBox_TextChanged(object? sender, TextChangedEventArgs e)
    {
        if (!_componentsReady || _suppressExtractTextChanged || _disposed || Volatile.Read(ref _operationActive) != 0)
        {
            return;
        }

        string path = ExtractArchiveBox.Text ?? string.Empty;
        ReleaseExtractAccessIfMismatched(path);
        BeginExtractHintLoad(path, debounce: true);
    }

    private void SetExtractArchivePath(string path)
    {
        ReleaseExtractAccessIfMismatched(path);
        SetExtractArchivePathWithoutHint(path);
        string? retainedParent = _extractOutputParentAccess is null
            ? null
            : GetLocalPath(_extractOutputParentAccess.Item);
        OutputFolderBox.Text = retainedParent is null
            ? SuggestOutputFolderPath(path)
            : SuggestOutputFolderPath(path, retainedParent);
        BeginExtractHintLoad(path, debounce: false);
    }

    private void SetExtractArchivePathWithoutHint(string path)
    {
        _suppressExtractTextChanged = true;
        try
        {
            ExtractArchiveBox.Text = path;
        }
        finally
        {
            _suppressExtractTextChanged = false;
        }
    }

    private void BeginExtractHintLoad(string archive, bool debounce)
    {
        int version = Interlocked.Increment(ref _hintLoadVersion);
        SetExtractHint(null, loaded: false);
        string path = archive.Trim();
        if (!File.Exists(path) || _disposed)
        {
            return;
        }

        _ = LoadExtractHintAsync(path, version, debounce);
    }

    private async Task LoadExtractHintAsync(string path, int version, bool debounce)
    {
        string? hint = null;
        string? error = null;
        try
        {
            using MacSecurityScopedResourceLease access = AcquireTransientExtractAccess(path)
                ?? throw new UnauthorizedAccessException(T("sandboxLeaseFailed"));
            if (debounce)
            {
                await Task.Delay(150, _lifetime.Token);
            }

            if (version != Volatile.Read(ref _hintLoadVersion))
            {
                return;
            }

            if (await _containers.LooksEncryptedAsync(path, _lifetime.Token))
            {
                hint = (await _containers.ReadContainerInfoAsync(path, _lifetime.Token)).Hint;
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or NotSupportedException or SecurityException)
        {
            error = exception.Message;
        }

        if (_disposed || version != Volatile.Read(ref _hintLoadVersion))
        {
            return;
        }

        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_disposed || version != Volatile.Read(ref _hintLoadVersion)
                || !string.Equals(ExtractArchiveBox.Text?.Trim(), path, StringComparison.Ordinal))
            {
                return;
            }

            if (error is null)
            {
                SetExtractHint(hint, loaded: true);
            }
            else
            {
                _extractHintUnavailable = true;
                _extractHintLoaded = false;
                _extractHint = null;
                RenderExtractHint();
                Log($"Container hint could not be loaded: {error}");
            }
        });
    }

    private void SetExtractHint(string? hint, bool loaded)
    {
        _extractHintLoaded = loaded;
        _extractHintUnavailable = false;
        _extractHint = string.IsNullOrWhiteSpace(hint) ? null : hint.Trim();
        RenderExtractHint();
    }

    private void RenderExtractHint()
    {
        if (!_componentsReady)
        {
            return;
        }

        ExtractHintText.Text = _extractHintUnavailable
            ? T("hintUnavailable")
            : !_extractHintLoaded
                ? T("hintNotLoaded")
                : _extractHint is null
                    ? T("hintNone")
                    : string.Format(CultureInfo.CurrentCulture, T("hintUnverified"), _extractHint);
    }

    private void SetErasePath(string path)
    {
        ErasePathBox.Text = path;
        EraseConfirmBox.IsChecked = false;
        EraseStatusText.Text = T("eraseNotAnalyzed");
    }

    private bool TryBeginProtectedOperation()
    {
        if (!_integrityTrusted || _disposed || Interlocked.CompareExchange(ref _operationActive, 1, 0) != 0)
        {
            return false;
        }

        OperationStatusText.Text = T("working");
        UpdateProtectedOperationControls();
        return true;
    }

    private void EndProtectedOperation()
    {
        Interlocked.Exchange(ref _operationActive, 0);
        if (_disposed)
        {
            DisposeStorageAccess();
            return;
        }

        OperationStatusText.Text = _integrityTrusted ? T("ready") : T("blocked");
        UpdateProtectedOperationControls();
        UpdateEntropyStatus(force: true);
    }

    private void UpdateProtectedOperationControls()
    {
        if (!_componentsReady)
        {
            return;
        }

        bool busy = Volatile.Read(ref _operationActive) != 0;
        bool interactive = !_disposed && !busy;
        CreatePanel.IsEnabled = interactive;
        ExtractPanel.IsEnabled = interactive;
        ErasePanel.IsEnabled = interactive;
        bool protectedEnabled = interactive && _integrityTrusted;
        CreateArchiveButton.IsEnabled = protectedEnabled;
        ExtractArchiveButton.IsEnabled = protectedEnabled;
        ListArchiveButton.IsEnabled = protectedEnabled;
        EmergencyRecoveryButton.IsEnabled = protectedEnabled;
        EraseContainerButton.IsEnabled = protectedEnabled;
    }

    private IProgress<string> Progress() => new Progress<string>(Log);

    private void Log(string? message)
    {
        if (string.IsNullOrWhiteSpace(message) || _disposed)
        {
            return;
        }

        if (!Dispatcher.UIThread.CheckAccess())
        {
            Dispatcher.UIThread.Post(() => Log(message));
            return;
        }

        string bounded = message.Length <= MaxLogEntryCharacters
            ? message
            : string.Concat(message.AsSpan(0, MaxLogEntryCharacters), " [entry truncated]");
        string entry = $"[{DateTime.Now:HH:mm:ss}] {bounded}{Environment.NewLine}";
        string existing = LogBox.Text ?? string.Empty;
        if (existing.Length + entry.Length > MaxLogCharacters)
        {
            int start = Math.Max(0, existing.Length - Math.Max(0, RetainedLogCharacters - entry.Length));
            int line = existing.IndexOf('\n', start);
            existing = existing[(line >= 0 ? line + 1 : start)..];
        }

        LogBox.Text = existing + entry;
        LogBox.CaretIndex = LogBox.Text.Length;
    }

    private Task<bool> ConfirmAsync(string message) => SecurityDialog.ShowAsync(
        this, T("confirmationTitle"), message, T("continue"), T("cancel"), SecurityDialogKind.DestructiveConfirmation);

    private Task InfoAsync(string message) => ShowAsync(message, SecurityDialogKind.Information);
    private Task WarnAsync(string message) => ShowAsync(message, SecurityDialogKind.Warning);
    private Task ErrorAsync(string message) => ShowAsync(message, SecurityDialogKind.Error);

    private async Task ShowAsync(string message, SecurityDialogKind kind)
    {
        _ = await SecurityDialog.ShowAsync(this, T(kind == SecurityDialogKind.Error ? "errorTitle" : "noticeTitle"), message, T("ok"), T("cancel"), kind);
    }

    private Task ShowBlockedAsync() => WarnAsync(T("integrityActionBlocked"));

    private static void CleanupFailedArchive(string archivePath)
    {
        RecoveryService.SecureDeleteRecoverySidecar(archivePath);
        ArchiveIntegrityService.DeleteManifests(archivePath);
        SecureFile.DeleteIfExists(archivePath);
    }

    private void TryCleanupFailedArchive(string archivePath)
    {
        try
        {
            CleanupFailedArchive(archivePath);
        }
        catch (Exception exception)
        {
            Log($"Cleanup failed: {exception}");
        }
    }

    private static readonly FilePickerFileType EncryptedArchiveType = new("Keep Vault encrypted archive")
    {
        Patterns = new[] { "*.kzpaq" },
        AppleUniformTypeIdentifiers = new[] { "public.data" },
    };

    private static readonly FilePickerFileType PlainArchiveType = new("ZPAQ archive")
    {
        Patterns = new[] { "*.zpaq" },
        AppleUniformTypeIdentifiers = new[] { "public.data" },
    };

    private static readonly FilePickerFileType AnyArchiveType = new("Keep Vault and ZPAQ archives")
    {
        Patterns = new[] { "*.kzpaq", "*.zpaq" },
        AppleUniformTypeIdentifiers = new[] { "public.data" },
    };

    private static readonly FilePickerFileType PdfType = new("PDF")
    {
        Patterns = new[] { "*.pdf" },
        AppleUniformTypeIdentifiers = new[] { "com.adobe.pdf" },
    };
}
