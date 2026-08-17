using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security;
using System.Text;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using KalynaArchiver.Services;
using Forms = System.Windows.Forms;
using DataFormats = System.Windows.DataFormats;
using DragEventArgs = System.Windows.DragEventArgs;
using DragDropEffects = System.Windows.DragDropEffects;
using MessageBox = System.Windows.MessageBox;
using MouseEventArgs = System.Windows.Input.MouseEventArgs;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using Point = System.Windows.Point;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace KalynaArchiver;

public sealed partial class MainWindow : Window, IDisposable
{
    private readonly ZpaqService _zpaq = new();
    private readonly KalynaContainerService _kalyna = new();
    private readonly IntegrityService _integrity = new();
    private readonly KeySheetService _keySheets = new();
    private readonly CryptographicEraseService _erase = new();
    private readonly RecoveryService _recovery = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly IAppSettingsStore _settingsStore;
    private readonly System.Windows.Input.MouseEventHandler _mouseMoveHandler;
    internal const string LanguageSettingsFile = "language.txt";
    internal const string CipherSuiteSettingsFile = "cipher-suite.txt";
    internal const string CompressionSettingsFile = "compression.txt";
    private const int DefaultCompressionLevel = 1;
    private const int MaxCompressionLevel = 5;
    private const int MaxLogCharacters = 1_000_000;
    private const int RetainedLogCharacters = 750_000;
    private const int MaxLogEntryCharacters = 64_000;
    private string _language = "en";
    private string? _keySheetFingerprint;
    private bool _componentsReady;
    private bool _extractHintLoaded;
    private bool _extractHintUnavailable;
    private bool _disposed;
    private bool _integrityTrusted;
    private bool _suppressExtractArchiveTextChanged;
    private int _extractHintLoadVersion;
    private int _protectedOperationActive;
    private string? _extractHint;
    private GeneratedArchiveEntropy? _generatedArchiveEntropy;
    private bool _generatedPasswordPairReady;

    // Remember the resolved status so re-applying the language (language switch) can re-render
    // the current result instead of falling back to the transient "checking/activating" text.
    private string? _integrityStatusKey = "integrityChecking";
    private string? _integrityStatusRawMessage;
    private System.Windows.Media.Brush _integrityStatusBrush = System.Windows.Media.Brushes.Gold;
    private string _captureStatusKey = "captureActivating";
    internal Task ExtractHintLoadTaskForTests { get; private set; } = Task.CompletedTask;

    private EncryptionSuite SelectedEncryptionSuite
    {
        get
        {
            if (CipherSuiteBox.SelectedItem is System.Windows.Controls.ComboBoxItem { Tag: string tag }
                && Enum.TryParse(tag, ignoreCase: false, out EncryptionSuite suite))
            {
                return suite;
            }

            return EncryptionSuiteCatalog.Default;
        }
    }

    public MainWindow()
        : this(new IsolatedStorageAppSettingsStore())
    {
    }

    internal MainWindow(IAppSettingsStore settingsStore)
    {
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        InitializeComponent();
        _language = LoadSavedLanguage();
        SelectLanguageItem(_language);
        SelectCipherSuiteItem(LoadSavedCipherSuite());
        CompressionBox.SelectedIndex = LoadSavedCompressionLevel();
        _componentsReady = true;
        UpdateProtectedOperationButtons();
        ApplyLanguage();
        CreatePasswordPanel.Opacity = EncryptBox.IsChecked == true ? 1.0 : 0.78;
        GeneratedPasswordFirstBox.Clear();
        GeneratedPasswordSecondBox.Clear();
        ResetKeySheetStatus();
        UpdateEntropyStatus();
        UpdatePasswordPolicyStatus();
        _mouseMoveHandler = MainWindow_PreviewMouseMove;
        AddHandler(System.Windows.Input.Mouse.PreviewMouseMoveEvent, _mouseMoveHandler, handledEventsToo: true);
        Loaded += MainWindow_Loaded;
        Closed += (_, _) => Dispose();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        UpdateProtectedOperationButtons();
        GeneratedArchiveEntropy? generatedArchiveEntropy = _generatedArchiveEntropy;
        _generatedArchiveEntropy = null;
        _generatedPasswordPairReady = false;
        if (_componentsReady)
        {
            CreatePasswordBox.Clear();
            CreatePasswordConfirmBox.Clear();
            GeneratedPasswordFirstBox.Clear();
            GeneratedPasswordSecondBox.Clear();
            ExtractPasswordBox.Clear();
            ExtractGeneratedPasswordFirstBox.Clear();
            ExtractGeneratedPasswordSecondBox.Clear();
        }

        generatedArchiveEntropy?.Dispose();

        _keySheetFingerprint = null;
        _extractHint = null;

        RemoveHandler(System.Windows.Input.Mouse.PreviewMouseMoveEvent, _mouseMoveHandler);
        Interlocked.Increment(ref _extractHintLoadVersion);
        _shutdown.Cancel();
        _shutdown.Dispose();
        _integrity.Dispose();
        GC.SuppressFinalize(this);
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        bool captureBlocked = WindowProtection.TryExcludeFromCapture(this);
        _captureStatusKey = captureBlocked ? "captureActive" : "captureUnavailable";
        ApplyCaptureStatusText();
        ProcessHardeningStatus hardening = ProcessHardening.LastStatus;
        Log($"Hardening: errorMode={hardening.ErrorModeSet}, WER={hardening.WerFlagsSet}, strictHandles={hardening.StrictHandlePolicySet}, extensionPointsDisabled={hardening.ExtensionPointsDisabled}, imageLoad={hardening.ImageLoadPolicySet}, system32DllSearch={hardening.DllSearchRestricted}");

        await CheckIntegrityAsync();
        Log($"ZPAQ: {_zpaq.ResolveExecutable() ?? T("notFound")}");
        if (_integrityTrusted)
        {
            Log(_kalyna.IsNativeKalynaAvailable
                ? T("kalynaAvailable")
                : T("kalynaMissing"));
            Log(_kalyna.IsNativeThreefishAvailable
                ? T("threefishAvailable")
                : T("threefishMissing"));
        }
        else
        {
            Log("Native cryptographic libraries were not loaded because application integrity is not trusted.");
        }

        UpdateEntropyStatus();
    }

    private void MainWindow_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (Volatile.Read(ref _protectedOperationActive) != 0)
        {
            return;
        }

        Point position = e.GetPosition(this);
        EntropyMixer.AddMouseSample(
            position.X,
            position.Y,
            e.Timestamp,
            System.Windows.Input.Mouse.LeftButton,
            System.Windows.Input.Mouse.RightButton,
            System.Windows.Input.Mouse.MiddleButton);
        UpdateEntropyStatus();
    }

    private async Task CheckIntegrityAsync()
    {
        _integrityTrusted = false;
        UpdateProtectedOperationButtons();
        try
        {
            IntegrityStatus status = await _integrity.CheckSelfAsync(_shutdown.Token);
            _integrityStatusKey = ResolveIntegrityStatusKey(status.Message);
            _integrityStatusRawMessage = _integrityStatusKey is null ? status.Message : null;
            _integrityStatusBrush = status.IsTrusted
                ? System.Windows.Media.Brushes.LightGreen
                : status.ExpectedSha3_512 is null || status.ExpectedSkein1024 is null
                    ? System.Windows.Media.Brushes.Gold
                    : System.Windows.Media.Brushes.OrangeRed;
            ApplyIntegrityStatusText();
            Log($"SHA3-512(App): {status.ActualSha3_512}");
            Log($"Skein-1024(App): {status.ActualSkein1024}");
            foreach (ToolIntegrityStatus component in status.Components)
            {
                Log($"Application component {Path.GetFileName(component.FilePath)}: dual-hash={component.HashMatches}; RSA+ML-DSA={component.HybridSignatureMatches}; Authenticode={component.SignatureState}");
            }
            IReadOnlyList<ToolIntegrityStatus> toolStatuses = await _integrity.CheckNativeToolsAsync(_shutdown.Token);
            foreach (ToolIntegrityStatus toolStatus in toolStatuses)
            {
                string name = Path.GetFileName(toolStatus.FilePath);
                string hashState = toolStatus.HashMatches ? "SHA3-512 + Skein-1024 ok" : "dual hash blocked";
                Log($"Native tool {name}: {hashState}; RSA+ML-DSA={toolStatus.HybridSignatureMatches}; Authenticode={toolStatus.SignatureState}; {toolStatus.SignatureMessage}");
            }

            bool nativeToolsTrusted = toolStatuses.Count == 5 && toolStatuses.All(tool => tool.IsTrusted);
            _integrityTrusted = status.IsTrusted && nativeToolsTrusted;
            if (!nativeToolsTrusted)
            {
                _integrityStatusKey = "integrityWarning";
                _integrityStatusRawMessage = null;
                _integrityStatusBrush = System.Windows.Media.Brushes.OrangeRed;
                ApplyIntegrityStatusText();
            }

            UpdateProtectedOperationButtons();
            if (!_integrityTrusted)
            {
                Log("Application signature or integrity policy did not pass: archive operations disabled.");
            }
        }
        catch (Exception ex)
        {
            _integrityTrusted = false;
            UpdateProtectedOperationButtons();
            _integrityStatusKey = "integrityFailed";
            _integrityStatusRawMessage = null;
            _integrityStatusBrush = System.Windows.Media.Brushes.OrangeRed;
            ApplyIntegrityStatusText();
            Log(ex.Message);
        }
    }

    private void ApplyIntegrityStatusText()
    {
        IntegrityText.Text = _integrityStatusRawMessage ?? (_integrityStatusKey is { } key ? T(key) : string.Empty);
        IntegrityText.Foreground = _integrityStatusBrush;
    }

    private void ApplyCaptureStatusText()
    {
        CaptureText.Text = T(_captureStatusKey);
    }

    private static string? ResolveIntegrityStatusKey(string message)
    {
        if (message.Contains("Dualmanifest", StringComparison.Ordinal))
        {
            return "integrityNoManifest";
        }

        if (message.StartsWith("Integritätsprüfung bestanden", StringComparison.Ordinal))
        {
            return "integrityOk";
        }

        if (message.StartsWith("WARNUNG", StringComparison.Ordinal))
        {
            return "integrityWarning";
        }

        return null;
    }

    private void LanguageBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LanguageBox.SelectedItem is System.Windows.Controls.ComboBoxItem item && item.Tag is string language)
        {
            _language = language;
            if (_componentsReady)
            {
                ApplyLanguage();
                SaveLanguage(_language);
            }
        }
    }

    private void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Multiselect = true, Title = T("chooseFilesDialog") };
        if (dialog.ShowDialog(this) == true)
        {
            foreach (string path in dialog.FileNames)
            {
                if (!InputList.Items.Contains(path))
                {
                    InputList.Items.Add(path);
                }
            }
        }
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog { Description = T("chooseFolderDialog"), UseDescriptionForTitle = true };
        if (dialog.ShowDialog() == Forms.DialogResult.OK && !InputList.Items.Contains(dialog.SelectedPath))
        {
            InputList.Items.Add(dialog.SelectedPath);
        }
    }

    private void ClearInputs_Click(object sender, RoutedEventArgs e)
    {
        InputList.Items.Clear();
    }

    private void ChooseArchive_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = T("saveArchiveDialog"),
            Filter = EncryptBox.IsChecked == true ? T("kalynaFilter") : T("zpaqFilter"),
            DefaultExt = EncryptBox.IsChecked == true ? ".kzpaq" : ".zpaq",
        };
        if (dialog.ShowDialog(this) == true)
        {
            ArchivePathBox.Text = NormalizeTargetArchivePath(dialog.FileName, EncryptBox.IsChecked == true);
            ResetKeySheetStatus();
        }
    }

    private void ChooseExtractArchive_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = T("chooseArchiveDialog"),
            Filter = T("archiveFilter"),
        };
        if (dialog.ShowDialog(this) == true)
        {
            SetExtractArchivePath(dialog.FileName);
        }
    }

    private void ChooseOutputFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog { Description = T("chooseOutputDialog"), UseDescriptionForTitle = true };
        if (dialog.ShowDialog() == Forms.DialogResult.OK)
        {
            OutputFolderBox.Text = dialog.SelectedPath;
        }
    }

    private void EncryptBox_Changed(object sender, RoutedEventArgs e)
    {
        if (CreatePasswordPanel is null || ArchivePathBox is null || CipherSuiteBox is null)
        {
            return;
        }

        bool encryptionEnabled = EncryptBox.IsChecked == true;
        CreatePasswordPanel.Opacity = encryptionEnabled ? 1.0 : 0.78;
        CipherSuiteBox.IsEnabled = encryptionEnabled;
        if (!string.IsNullOrWhiteSpace(ArchivePathBox.Text))
        {
            ArchivePathBox.Text = NormalizeTargetArchivePath(ArchivePathBox.Text, encryptionEnabled);
            ResetKeySheetStatus();
        }
    }

    private void CipherSuiteBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!_componentsReady)
        {
            return;
        }

        ResetKeySheetStatus();
        SaveCipherSuite(SelectedEncryptionSuite);
        Log(string.Format(T("cipherSuiteSelected"), EncryptionSuiteCatalog.Get(SelectedEncryptionSuite).DisplayName));
    }

    private void CompressionBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!_componentsReady)
        {
            return;
        }

        SaveCompressionLevel(CompressionBox.SelectedIndex);
    }

    private async void CreateArchive_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            return;
        }

        string? createdArchivePath = null;
        GeneratedArchiveEntropy? preparedEntropy = null;
        try
        {
            var inputs = InputList.Items.Cast<string>().ToArray();
            if (inputs.Length == 0)
            {
                MessageBox.Show(this, T("inputsMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string archivePath = NormalizeTargetArchivePath(ArchivePathBox.Text.Trim(), EncryptBox.IsChecked == true);
            if (string.IsNullOrWhiteSpace(archivePath))
            {
                MessageBox.Show(this, T("targetMissing"), T("targetMissingTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            ArchivePathBox.Text = archivePath;
            EnsureArchiveTargetIsSafe(archivePath, inputs);

            if (EncryptBox.IsChecked == true)
            {
                EnsurePasswordPair();
                preparedEntropy = _generatedArchiveEntropy is { HasPendingEncryptionParameters: true } current
                    ? current
                    : null;
                if (preparedEntropy is null)
                {
                    EnsureEntropyReady(EntropyPurpose.Salt);
                    EnsureEntropyReady(EntropyPurpose.NonceFirst);
                    EnsureEntropyReady(EntropyPurpose.NonceSecond);
        EnsureEntropyReady(EntropyPurpose.NonceThird);
                    EnsureEntropyReady(EntropyPurpose.NonceThird);
                }

                EnsureKeySheetHandled(archivePath);
                if (!_kalyna.IsNativeSuiteAvailable(SelectedEncryptionSuite))
                {
                    throw new InvalidOperationException(string.Format(
                        T("selectedSuiteMissing"),
                        EncryptionSuiteCatalog.Get(SelectedEncryptionSuite).DisplayName));
                }
            }

            int compressionLevel = CompressionBox.SelectedIndex < 0 ? 1 : CompressionBox.SelectedIndex;
            Log(T("creatingZpaq"));

            if (EncryptBox.IsChecked == true)
            {
                EncryptionSuite suite = SelectedEncryptionSuite;
                Log(string.Format(T("encryptingStreaming"), EncryptionSuiteCatalog.Get(suite).DisplayName));
                async Task EncryptArchiveAsync(Stream zpaqStream, CancellationToken cancellationToken)
                {
                    if (preparedEntropy is null)
                    {
                        await _kalyna.EncryptZpaqStreamAsync(
                            zpaqStream,
                            archivePath,
                            CreatePasswordBox.Password,
                            GeneratedPasswordFirstBox.Text,
                            GeneratedPasswordSecondBox.Text,
                            suite,
                            HintBox.Text.Trim(),
                            Progress(),
                            cancellationToken);
                    }
                    else
                    {
                        await _kalyna.EncryptZpaqStreamWithPreparedEntropyAsync(
                            zpaqStream,
                            archivePath,
                            CreatePasswordBox.Password,
                            GeneratedPasswordFirstBox.Text,
                            GeneratedPasswordSecondBox.Text,
                            suite,
                            preparedEntropy,
                            HintBox.Text.Trim(),
                            Progress(),
                            cancellationToken);
                    }

                    createdArchivePath = archivePath;
                }

                ProcessResult result = await _zpaq.AddStreamingAsync(
                    inputs,
                    compressionLevel,
                    EncryptArchiveAsync,
                    Progress(),
                    _shutdown.Token);
                if (!result.Succeeded)
                {
                    CleanupFailedArchiveArtifacts(archivePath);
                    createdArchivePath = null;
                    Log(result.StandardError);
                    MessageBox.Show(this, T("zpaqCreateFailed"), T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
            else
            {
                ProcessResult result = await _zpaq.AddAsync(archivePath, inputs, compressionLevel, Progress(), _shutdown.Token);
                if (!result.Succeeded)
                {
                    Log(result.StandardError);
                    MessageBox.Show(this, T("zpaqCreateFailed"), T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                createdArchivePath = archivePath;
            }

            if (EncryptBox.IsChecked == true)
            {
                await _recovery.CreateAuthenticatedAsync(
                    archivePath,
                    CreatePasswordBox.Password,
                    GeneratedPasswordFirstBox.Text,
                    GeneratedPasswordSecondBox.Text,
                    Progress(),
                    _shutdown.Token);
            }
            else
            {
                await _recovery.CreateAsync(archivePath, Progress(), _shutdown.Token);
            }
            createdArchivePath = null;
            SaveCompressionLevel(compressionLevel);
            if (EncryptBox.IsChecked == true)
            {
                SaveCipherSuite(SelectedEncryptionSuite);
            }

            ClearCreateSecrets();
            Log($"Fertig: {archivePath}");
            MessageBox.Show(this, T("archiveCreated"), T("doneTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            if (createdArchivePath is not null)
            {
                try
                {
                    CleanupFailedArchiveArtifacts(createdArchivePath);
                }
                catch (Exception cleanupException)
                {
                    Log($"Cleanup failed: {cleanupException}");
                }
            }

            UpdateEntropyStatus();
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void ExtractArchive_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text.Trim();
            string output = OutputFolderBox.Text.Trim();
            if (File.Exists(archive) && string.IsNullOrWhiteSpace(output))
            {
                output = SuggestOutputFolderPath(archive);
                OutputFolderBox.Text = output;
            }

            if (!File.Exists(archive) || string.IsNullOrWhiteSpace(output))
            {
                MessageBox.Show(this, T("extractInputMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            archive = await PrepareArchiveForUseAsync(archive);
            bool encrypted = await _kalyna.LooksEncryptedAsync(archive, _shutdown.Token);

            ProcessResult result;
            if (encrypted)
            {
                (KalynaContainerInfo info, string effectiveArchive) = await ReadContainerInfoWithRecoveryAsync(archive);
                archive = effectiveArchive;
                ExtractArchiveBox.Text = archive;
                Log($"Cipher suite: {info.Algorithm}");
                SetExtractHint(info.Hint, loaded: true);
                EnsurePasswordPresent();
                EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text);
                EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text);

                Log(T("extractingStreaming"));
                result = await ExecuteEncryptedWithRecoveryRetryAsync(
                    archive,
                    effectivePath => _zpaq.ExtractStreamingAsync(
                        (zpaqInput, ct) => _kalyna.DecryptToStreamAsync(
                            effectivePath,
                            ExtractPasswordBox.Password,
                            ExtractGeneratedPasswordFirstBox.Text,
                            ExtractGeneratedPasswordSecondBox.Text,
                            zpaqInput,
                            Progress(),
                            ct),
                        output,
                        Progress(),
                        _shutdown.Token));
            }
            else
            {
                Log(T("extracting"));
                result = await _zpaq.ExtractAsync(archive, output, Progress(), _shutdown.Token);
            }

            if (!result.Succeeded)
            {
                Log(result.StandardError);
                MessageBox.Show(this, T("zpaqExtractFailed"), T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            ClearExtractSecrets();
            Log($"Entpackt nach: {output}");
            MessageBox.Show(this, T("archiveExtracted"), T("doneTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void ListArchive_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text.Trim();
            if (!File.Exists(archive))
            {
                MessageBox.Show(this, T("archiveMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            archive = await PrepareArchiveForUseAsync(archive);
            bool encrypted = await _kalyna.LooksEncryptedAsync(archive, _shutdown.Token);

            ProcessResult result;
            if (encrypted)
            {
                (KalynaContainerInfo info, string effectiveArchive) = await ReadContainerInfoWithRecoveryAsync(archive);
                archive = effectiveArchive;
                ExtractArchiveBox.Text = archive;
                Log($"Cipher suite: {info.Algorithm}");
                SetExtractHint(info.Hint, loaded: true);
                EnsurePasswordPresent();
                EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text);
                EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text);

                result = await ExecuteEncryptedWithRecoveryRetryAsync(
                    archive,
                    effectivePath => _zpaq.ListStreamingAsync(
                        (zpaqInput, ct) => _kalyna.DecryptToStreamAsync(
                            effectivePath,
                            ExtractPasswordBox.Password,
                            ExtractGeneratedPasswordFirstBox.Text,
                            ExtractGeneratedPasswordSecondBox.Text,
                            zpaqInput,
                            Progress(),
                            ct),
                        Progress(),
                        _shutdown.Token));
            }
            else
            {
                result = await _zpaq.ListAsync(archive, Progress(), _shutdown.Token);
            }

            Log(result.StandardOutput);
            Log(result.StandardError);
            if (!result.Succeeded)
            {
                Log(result.StandardError);
            }
            else
            {
                ClearExtractSecrets();
            }
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private async void EmergencyRecovery_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            return;
        }

        try
        {
            string archive = ExtractArchiveBox.Text.Trim();
            if (!File.Exists(archive))
            {
                MessageBox.Show(this, T("archiveMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            RecoveryProtectionMode? mode = await _recovery.TryReadProtectionModeAsync(
                archive,
                _shutdown.Token);
            if (mode is null)
            {
                MessageBox.Show(this, T("emergencyRecoveryMissing"), T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            MessageBoxResult confirmation = MessageBox.Show(
                this,
                mode == RecoveryProtectionMode.DualAuthenticatedEncrypted
                    ? T("emergencyRecoveryEncryptedWarning")
                    : T("emergencyRecoveryPlainWarning"),
                T("emergencyRecoveryTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }

            RecoveryRepairResult recovery;
            if (mode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
            {
                EnsurePasswordPresent();
                EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text);
                EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text);
                recovery = await _recovery.RecoverToNewFileAuthenticatedAsync(
                    archive,
                    ExtractPasswordBox.Password,
                    ExtractGeneratedPasswordFirstBox.Text,
                    ExtractGeneratedPasswordSecondBox.Text,
                    Progress(),
                    _shutdown.Token);
            }
            else
            {
                recovery = await _recovery.RecoverToNewFileAsync(
                    archive,
                    Progress(),
                    _shutdown.Token);
            }

            string effectivePath = recovery.OutputPath ?? archive;
            ExtractArchiveBox.Text = effectivePath;
            OutputFolderBox.Text = SuggestOutputFolderPath(effectivePath);
            Log(recovery.Message);
            Log(string.Format(T("recoveryNewFile"), effectivePath));
            MessageBox.Show(this, recovery.Message, T("doneTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        LogBox.Clear();
    }

    private void ClearCreateSecrets_Click(object sender, RoutedEventArgs e)
    {
        ClearCreateSecrets();
    }

    private void ClearExtractSecrets_Click(object sender, RoutedEventArgs e)
    {
        ClearExtractSecrets();
    }

    private void ClearCreateSecrets()
    {
        GeneratedArchiveEntropy? generatedArchiveEntropy = _generatedArchiveEntropy;
        _generatedArchiveEntropy = null;
        _generatedPasswordPairReady = false;
        CreatePasswordBox.Clear();
        CreatePasswordConfirmBox.Clear();
        GeneratedPasswordFirstBox.Clear();
        GeneratedPasswordSecondBox.Clear();
        generatedArchiveEntropy?.Dispose();
        ResetKeySheetStatus();
        UpdateEntropyStatus();
        UpdatePasswordPolicyStatus();
    }

    private void ClearExtractSecrets()
    {
        ExtractPasswordBox.Clear();
        ExtractGeneratedPasswordFirstBox.Clear();
        ExtractGeneratedPasswordSecondBox.Clear();
    }

    private static void CleanupFailedArchiveArtifacts(string archivePath)
    {
        RecoveryService.SecureDeleteRecoverySidecar(archivePath);
        ArchiveIntegrityService.DeleteManifests(archivePath);
        SecureFile.DeleteIfExists(archivePath);
    }

    private async Task<string> PrepareArchiveForUseAsync(string archive)
    {
        if (await _kalyna.LooksEncryptedAsync(archive, _shutdown.Token))
        {
            return archive;
        }

        RecoveryProtectionMode? mode = await _recovery.TryReadProtectionModeAsync(
            archive,
            _shutdown.Token);
        if (mode is null)
        {
            if (HasEncryptedArchiveExtension(archive))
            {
                throw new InvalidDataException(T("encryptedHeaderWithoutRecovery"));
            }

            return archive;
        }

        RecoveryRepairResult recovery;
        if (mode == RecoveryProtectionMode.DualAuthenticatedEncrypted)
        {
            EnsurePasswordPresent();
            EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text);
            EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text);
            recovery = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Password,
                ExtractGeneratedPasswordFirstBox.Text,
                ExtractGeneratedPasswordSecondBox.Text,
                Progress(),
                _shutdown.Token);
        }
        else
        {
            recovery = await _recovery.VerifyAndRepairAsync(
                archive,
                Progress(),
                _shutdown.Token);
        }

        string effectivePath = recovery.OutputPath ?? archive;
        if (!string.Equals(effectivePath, archive, StringComparison.OrdinalIgnoreCase))
        {
            ExtractArchiveBox.Text = effectivePath;
            Log(string.Format(T("recoveryNewFile"), effectivePath));
        }

        return effectivePath;
    }

    internal static bool HasEncryptedArchiveExtension(string path)
    {
        return string.Equals(
            Path.GetExtension(path),
            ".kzpaq",
            StringComparison.OrdinalIgnoreCase);
    }

    private async Task<(KalynaContainerInfo Info, string ArchivePath)> ReadContainerInfoWithRecoveryAsync(string archive)
    {
        try
        {
            return (await _kalyna.ReadContainerInfoAsync(archive, _shutdown.Token), archive);
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
        {
            EnsurePasswordPresent();
            EnsureGeneratedPassword(ExtractGeneratedPasswordFirstBox.Text);
            EnsureGeneratedPassword(ExtractGeneratedPasswordSecondBox.Text);
            RecoveryRepairResult recovery = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Password,
                ExtractGeneratedPasswordFirstBox.Text,
                ExtractGeneratedPasswordSecondBox.Text,
                Progress(),
                _shutdown.Token);
            if (!recovery.Repaired)
            {
                throw;
            }

            string effectivePath = recovery.OutputPath ?? archive;
            Log(string.Format(T("recoveryNewFile"), effectivePath));
            return (await _kalyna.ReadContainerInfoAsync(effectivePath, _shutdown.Token), effectivePath);
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
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or EndOfStreamException)
        {
            RecoveryRepairResult recovery = await _recovery.VerifyAndRepairAuthenticatedAsync(
                archive,
                ExtractPasswordBox.Password,
                ExtractGeneratedPasswordFirstBox.Text,
                ExtractGeneratedPasswordSecondBox.Text,
                Progress(),
                _shutdown.Token);
            if (!recovery.Repaired)
            {
                throw;
            }

            string effectivePath = recovery.OutputPath ?? archive;
            ExtractArchiveBox.Text = effectivePath;
            Log(string.Format(T("recoveryNewFile"), effectivePath));
            Log(T("retryAfterRecovery"));
            return await operation(effectivePath);
        }
    }

    private void GeneratePassword_Click(object sender, RoutedEventArgs e)
    {
        if (Volatile.Read(ref _protectedOperationActive) != 0)
        {
            return;
        }

        try
        {
            EncryptBox.IsChecked = true;
            GenerateGeneratedPassword(log: true);
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            UpdateEntropyStatus();
        }
    }

    private void SaveKeySheet_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            KeySheetData data = BuildCurrentKeySheetData();
            string archiveDirectory = Path.GetDirectoryName(data.ArchivePath) ?? Environment.CurrentDirectory;
            string archiveStem = Path.GetFileNameWithoutExtension(data.ArchivePath);
            var dialog = new SaveFileDialog
            {
                Title = T("saveTestKeySheetDialog"),
                Filter = T("pdfFilter"),
                DefaultExt = ".pdf",
                InitialDirectory = archiveDirectory,
                FileName = $"{archiveStem}-key-sheets-test-export.pdf",
            };

            if (dialog.ShowDialog(this) == true)
            {
                _keySheets.SaveTestPdf(data, dialog.FileName);
                MarkKeySheetHandled(data);
                Log(string.Format(T("keySheetTestPdfSavedLog"), dialog.FileName));
            }
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void PrintKeySheet_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            KeySheetData data = BuildCurrentKeySheetData();

            // Use the classic GDI print dialog + GDI printing instead of WPF's
            // System.Printing pipeline. Some printer drivers (e.g. the Microsoft IPP Class
            // Driver) fail every PrintTicket<->DEVMODE conversion with 0x80004005, which makes
            // the WPF PrintDialog unusable even for selecting a different, working printer.
            using var printDocument = new System.Drawing.Printing.PrintDocument();
            if (!printDocument.PrinterSettings.IsValid)
            {
                string? firstValid = KeySheetService.FirstValidPhysicalPrinter();
                if (firstValid is not null)
                {
                    printDocument.PrinterSettings.PrinterName = firstValid;
                }
            }

            using var dialog = new Forms.PrintDialog
            {
                Document = printDocument,
                UseEXDialog = false,
                AllowPrintToFile = false,
                AllowSelection = false,
                AllowSomePages = false,
            };

            if (dialog.ShowDialog() == Forms.DialogResult.OK)
            {
                KeySheetService.EnsurePhysicalPrinter(dialog.PrinterSettings.PrinterName);
                _keySheets.PrintKeySheets(dialog.PrinterSettings, data);
                MarkKeySheetHandled(data);
                Log(T("keySheetPrintedLog"));
            }
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ChooseEraseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = T("chooseEraseDialog"),
            Filter = T("kalynaFilter"),
        };
        if (dialog.ShowDialog(this) == true)
        {
            SetErasePath(dialog.FileName);
        }
    }

    private async void AnalyzeErase_Click(object sender, RoutedEventArgs e)
    {
        await AnalyzeEraseTargetAsync();
    }

    private async void EraseContainer_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginProtectedOperation())
        {
            return;
        }

        try
        {
            string path = ErasePathBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                MessageBox.Show(this, T("eraseMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (EraseConfirmBox.IsChecked != true)
            {
                MessageBox.Show(this, T("eraseConfirmMissing"), T("missingInputTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            CryptoEraseAnalysis analysis = await _erase.AnalyzeAsync(path, _shutdown.Token);
            EraseStatusText.Text = analysis.Message;
            EraseHardwareNoticeText.Text = analysis.HardwareNotice;
            if (!analysis.IsEncryptedContainer)
            {
                MessageBox.Show(this, analysis.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            MessageBoxResult confirm = MessageBox.Show(
                this,
                T("eraseFinalConfirm"),
                T("eraseTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }

            CryptoEraseResult result = await _erase.EraseEncryptedContainerAsync(path, Progress(), _shutdown.Token);
            EraseStatusText.Text = result.Message;
            ErasePathBox.Clear();
            EraseConfirmBox.IsChecked = false;
            Log(result.Message);
            MessageBox.Show(this, result.Message, T("doneTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EndProtectedOperation();
        }
    }

    private void ErasePathBox_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.EraseTarget);
    }

    private void ErasePathBox_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.EraseTarget);
    }

    private void Global_PreviewDragOver(object sender, DragEventArgs e)
    {
        string[] paths = GetDroppedPaths(e);
        DropTarget target = ResolveDropTargetFromEvent(e, paths);
        e.Effects = paths.Length > 0 && CanDrop(paths, target) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Global_PreviewDrop(object sender, DragEventArgs e)
    {
        string[] paths = GetDroppedPaths(e);
        DropTarget target = ResolveDropTargetFromEvent(e, paths);
        DropResult result = ApplyDroppedPaths(paths, target);
        e.Effects = result == DropResult.None ? DragDropEffects.None : DragDropEffects.Copy;
        e.Handled = true;
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.Auto);
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.Auto);
    }

    private void InputList_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.Inputs);
    }

    private void InputList_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.Inputs);
    }

    private void ArchivePathBox_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.TargetArchive);
    }

    private void ArchivePathBox_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.TargetArchive);
    }

    private void ExtractArchiveBox_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.ExtractArchive);
    }

    private void ExtractArchiveBox_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.ExtractArchive);
    }

    private void ExtractArchiveBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_componentsReady
            || _suppressExtractArchiveTextChanged
            || _disposed
            || Volatile.Read(ref _protectedOperationActive) != 0)
        {
            return;
        }

        BeginExtractHintLoad(ExtractArchiveBox.Text, debounce: true);
    }

    private void OutputFolderBox_DragOver(object sender, DragEventArgs e)
    {
        SetDropEffect(e, DropTarget.OutputFolder);
    }

    private void OutputFolderBox_Drop(object sender, DragEventArgs e)
    {
        HandleDrop(e, DropTarget.OutputFolder);
    }

    private void EnsurePasswordPair()
    {
        EnsureGeneratedPassword(GeneratedPasswordFirstBox.Text);
        EnsureGeneratedPassword(GeneratedPasswordSecondBox.Text);
        EnsureUserPasswordForCreation(
            CreatePasswordBox.Password,
            GeneratedPasswordFirstBox.Text,
            GeneratedPasswordSecondBox.Text);
        if (!string.Equals(CreatePasswordBox.Password, CreatePasswordConfirmBox.Password, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("passwordMismatch"));
        }
    }

    private void EnsurePasswordPresent()
    {
        EnsurePasswordLength(ExtractPasswordBox.Password);
    }

    private void EnsurePasswordLength(string password)
    {
        if (password.Length < PasswordKeyService.MinPasswordLength || password.Length > PasswordKeyService.MaxPasswordLength)
        {
            throw new InvalidOperationException(T("passwordLength"));
        }
    }

    private void EnsureUserPasswordForCreation(string userPassword, string firstGeneratedPassword, string secondGeneratedPassword)
    {
        try
        {
            PasswordKeyService.ValidateUserPasswordForCreation(userPassword, firstGeneratedPassword, secondGeneratedPassword);
        }
        catch (PasswordPolicyException ex)
        {
            throw new InvalidOperationException(FormatPasswordPolicyViolations(ex.Analysis), ex);
        }
    }

    private void EnsureGeneratedPassword(string generatedPassword)
    {
        try
        {
            _ = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new InvalidOperationException(T("generatedPasswordLength"), ex);
        }
    }

    private void EnsureEntropyReady(EntropyPurpose purpose)
    {
        if (EntropyMixer.HasRequiredSamples(purpose))
        {
            return;
        }

        string label = purpose switch
        {
            EntropyPurpose.GeneratedPasswordFirst => T("entropyGeneratedPasswordFirst"),
            EntropyPurpose.GeneratedPasswordSecond => T("entropyGeneratedPasswordSecond"),
            EntropyPurpose.Salt => T("entropySalt"),
            EntropyPurpose.NonceFirst => T("entropyNonceFirst"),
            EntropyPurpose.NonceSecond => T("entropyNonceSecond"),
            EntropyPurpose.NonceThird => T("entropyNonceThird"),
            _ => purpose.ToString(),
        };
        long current = EntropyMixer.GetSampleCount(purpose);
        throw new InvalidOperationException(string.Format(
            T("entropyNotReady"),
            label,
            EntropyMixer.RequiredMouseSamplesPerPurpose,
            current,
            EntropyMixer.MissingSamples(purpose)));
    }

    private void EnsureKeySheetHandled(string archivePath)
    {
        string expected = BuildKeySheetFingerprint(
            archivePath,
            SelectedEncryptionSuite,
            GeneratedPasswordFirstBox.Text,
            GeneratedPasswordSecondBox.Text);
        if (!string.Equals(_keySheetFingerprint, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(T("keySheetRequired"));
        }
    }

    private KeySheetData BuildCurrentKeySheetData()
    {
        EnsureGeneratedPassword(GeneratedPasswordFirstBox.Text);
        EnsureGeneratedPassword(GeneratedPasswordSecondBox.Text);
        string archivePath = NormalizeTargetArchivePath(ArchivePathBox.Text.Trim(), encrypted: true);
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            throw new InvalidOperationException(T("targetMissing"));
        }

        ArchivePathBox.Text = archivePath;
        EncryptBox.IsChecked = true;
        return new KeySheetData(
            Path.GetFullPath(archivePath),
            SelectedEncryptionSuite,
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordFirstBox.Text),
            PasswordKeyService.NormalizeGeneratedPassword(GeneratedPasswordSecondBox.Text),
            DateTime.Now);
    }

    private void GenerateGeneratedPassword(bool log)
    {
        EnsureEntropyReady(EntropyPurpose.GeneratedPasswordFirst);
        EnsureEntropyReady(EntropyPurpose.GeneratedPasswordSecond);
        EnsureEntropyReady(EntropyPurpose.Salt);
        EnsureEntropyReady(EntropyPurpose.NonceFirst);
        EnsureEntropyReady(EntropyPurpose.NonceSecond);
        GeneratedArchiveEntropy? generatedEntropy = EntropyMixer.CreateArchiveEntropy();
        try
        {
            GeneratedArchiveEntropy? previousEntropy = _generatedArchiveEntropy;
            GeneratedPasswordFirstBox.Text = generatedEntropy.FirstPassword;
            GeneratedPasswordSecondBox.Text = generatedEntropy.SecondPassword;
            _generatedArchiveEntropy = generatedEntropy;
            generatedEntropy = null;
            _generatedPasswordPairReady = true;
            previousEntropy?.Dispose();
            ResetKeySheetStatus();
            UpdateEntropyStatus();
            UpdatePasswordPolicyStatus();
            if (log)
            {
                Log(T("generatedPasswordLog"));
            }
        }
        finally
        {
            generatedEntropy?.Dispose();
        }
    }

    private void ResetKeySheetStatus()
    {
        _keySheetFingerprint = null;
        if (_componentsReady)
        {
            KeySheetStatusText.Text = T("keySheetMissing");
            KeySheetStatusText.Foreground = System.Windows.Media.Brushes.Gold;
        }
    }

    private void MarkKeySheetHandled(KeySheetData data)
    {
        _keySheetFingerprint = BuildKeySheetFingerprint(
            data.ArchivePath,
            data.Suite,
            data.FirstGeneratedPassword,
            data.SecondGeneratedPassword);
        KeySheetStatusText.Text = T("keySheetHandled");
        KeySheetStatusText.Foreground = System.Windows.Media.Brushes.LightGreen;
    }

    private static string BuildKeySheetFingerprint(
        string archivePath,
        EncryptionSuite suite,
        string firstGeneratedPassword,
        string secondGeneratedPassword)
    {
        using LockedSensitiveBuffer pathBytes = LockedSensitiveBuffer.Encode(
            Path.GetFullPath(archivePath).ToUpperInvariant(),
            Encoding.UTF8);
        using LockedSensitiveBuffer suiteBytes = LockedSensitiveBuffer.Encode(suite.ToString(), Encoding.ASCII);
        using LockedSensitiveBuffer firstBytes = LockedSensitiveBuffer.Encode(
            PasswordKeyService.NormalizeGeneratedPassword(firstGeneratedPassword),
            Encoding.ASCII);
        using LockedSensitiveBuffer secondBytes = LockedSensitiveBuffer.Encode(
            PasswordKeyService.NormalizeGeneratedPassword(secondGeneratedPassword),
            Encoding.ASCII);
        using LockedSensitiveBuffer sha3Fingerprint = LockedSensitiveBuffer.Create(SHA3_512.HashSizeInBytes);
        using LockedSensitiveBuffer skeinFingerprint = LockedSensitiveBuffer.Create(Skein1024Digest.DigestSize);
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
        using var skein = new Skein1024Digest();
        AppendFingerprintPart(hasher, skein, "Kalyna-ZPAQ/v8/key-sheet-fingerprint"u8);
        AppendFingerprintPart(hasher, skein, pathBytes.Bytes);
        AppendFingerprintPart(hasher, skein, suiteBytes.Bytes);
        AppendFingerprintPart(hasher, skein, firstBytes.Bytes);
        AppendFingerprintPart(hasher, skein, secondBytes.Bytes);
        if (!hasher.TryGetHashAndReset(sha3Fingerprint.Bytes, out int sha3Written)
            || sha3Written != SHA3_512.HashSizeInBytes)
        {
            throw new CryptographicException("SHA3-512 returned an invalid key-sheet fingerprint length.");
        }

        skein.GetHashAndReset(skeinFingerprint.Bytes);
        return $"{Convert.ToHexString(sha3Fingerprint.Bytes)}:{Convert.ToHexString(skeinFingerprint.Bytes)}";
    }

    private static void AppendFingerprintPart(
        IncrementalHash hasher,
        Skein1024Digest skein,
        ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, value.Length);
        hasher.AppendData(length);
        hasher.AppendData(value);
        skein.AppendData(length);
        skein.AppendData(value);
        CryptographicOperations.ZeroMemory(length);
    }

    private void SetErasePath(string path)
    {
        ErasePathBox.Text = path;
        EraseConfirmBox.IsChecked = false;
        EraseStatusText.Text = T("eraseNotAnalyzed");
    }

    private async Task AnalyzeEraseTargetAsync()
    {
        try
        {
            CryptoEraseAnalysis analysis = await _erase.AnalyzeAsync(ErasePathBox.Text.Trim(), _shutdown.Token);
            EraseStatusText.Text = analysis.Message;
            EraseHardwareNoticeText.Text = analysis.HardwareNotice;
            Log(analysis.Message);
            Log(analysis.HardwareNotice);
        }
        catch (Exception ex)
        {
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, T("errorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool TryBeginProtectedOperation()
    {
        if (!_integrityTrusted || _disposed
            || Interlocked.CompareExchange(ref _protectedOperationActive, 1, 0) != 0)
        {
            return false;
        }

        UpdateProtectedOperationButtons();
        return true;
    }

    private void EndProtectedOperation()
    {
        Interlocked.Exchange(ref _protectedOperationActive, 0);
        UpdateProtectedOperationButtons();
    }

    private void UpdateProtectedOperationButtons()
    {
        if (!_componentsReady)
        {
            return;
        }

        bool busy = Volatile.Read(ref _protectedOperationActive) != 0;
        bool interactive = !busy && !_disposed;
        CreatePanel.IsEnabled = interactive;
        ExtractPanel.IsEnabled = interactive;
        ErasePanel.IsEnabled = interactive;
        bool enabled = !_disposed
            && _integrityTrusted
            && !busy;
        CreateArchiveButton.IsEnabled = enabled;
        ExtractArchiveButton.IsEnabled = enabled;
        ListArchiveButton.IsEnabled = enabled;
        EmergencyRecoveryButton.IsEnabled = enabled;
        EraseContainerButton.IsEnabled = enabled;
    }

    private IProgress<string> Progress()
    {
        return new Progress<string>(Log);
    }

    private void Log(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        string boundedMessage = message.Length <= MaxLogEntryCharacters
            ? message
            : string.Concat(message.AsSpan(0, MaxLogEntryCharacters), " [entry truncated]");
        string entry = $"[{DateTime.Now:HH:mm:ss}] {boundedMessage}{Environment.NewLine}";
        Dispatcher.Invoke(() =>
        {
            if (LogBox.Text.Length + entry.Length > MaxLogCharacters)
            {
                string existing = LogBox.Text;
                int desiredExistingCharacters = Math.Max(0, RetainedLogCharacters - entry.Length);
                int start = Math.Max(0, existing.Length - desiredExistingCharacters);
                int lineBoundary = existing.IndexOf('\n', start);
                if (lineBoundary >= 0)
                {
                    start = lineBoundary + 1;
                }

                LogBox.Text = existing[start..];
                LogBox.CaretIndex = LogBox.Text.Length;
            }

            LogBox.AppendText(entry);
            LogBox.ScrollToEnd();
        });
    }

    private void UpdateEntropyStatus()
    {
        if (!_componentsReady)
        {
            return;
        }

        EntropyPoolStatus status = EntropyMixer.GetPoolStatus();
        bool entropyReady = status.Minimum >= EntropyMixer.RequiredMouseSamplesPerPurpose;

        GeneratePasswordButton.IsEnabled = entropyReady;
        GeneratePasswordButton.Content = T(_generatedPasswordPairReady ? "regeneratePassword" : "generatePassword");
        string statusKey = !_generatedPasswordPairReady
            ? "entropyStatusCollecting"
            : _generatedArchiveEntropy is { HasPendingEncryptionParameters: true }
                ? "entropyStatusPrepared"
                : "entropyStatusRetry";
        EntropyStatusText.Text = string.Format(
            T(statusKey),
            status.Total,
            status.GeneratedPasswordFirst,
            status.GeneratedPasswordSecond,
            status.Salt,
            status.NonceFirst,
            status.NonceSecond,
            status.NonceThird,
            EntropyMixer.RequiredMouseSamplesPerPurpose);
        EntropyStatusText.Foreground = statusKey == "entropyStatusPrepared"
            ? System.Windows.Media.Brushes.LightGreen
            : statusKey == "entropyStatusRetry"
                ? System.Windows.Media.Brushes.Gold
                : System.Windows.Media.Brushes.Cyan;
    }

    private void CreatePasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        UpdatePasswordPolicyStatus();
    }

    private void UpdatePasswordPolicyStatus()
    {
        if (!_componentsReady || PasswordEntropyStatusText is null || PasswordPolicyStatusText is null)
        {
            return;
        }

        PasswordPolicyAnalysis analysis = PasswordKeyService.AnalyzeUserPassword(
            CreatePasswordBox.Password,
            GeneratedPasswordFirstBox.Text,
            GeneratedPasswordSecondBox.Text);
        PasswordEntropyStatusText.Text = string.Format(
            T("passwordEntropyStatus"),
            analysis.ConservativeEntropyBits.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture),
            PasswordKeyService.MinimumConservativeEntropyBits.ToString("0", System.Globalization.CultureInfo.InvariantCulture));
        PasswordEntropyStatusText.Foreground = analysis.ConservativeEntropyBits >= PasswordKeyService.MinimumConservativeEntropyBits
            ? System.Windows.Media.Brushes.LightGreen
            : System.Windows.Media.Brushes.Gold;

        if (analysis.IsAccepted)
        {
            PasswordPolicyStatusText.Text = T("passwordPolicyAccepted");
            PasswordPolicyStatusText.Foreground = System.Windows.Media.Brushes.LightGreen;
        }
        else
        {
            PasswordPolicyStatusText.Text = FormatPasswordPolicyViolations(analysis);
            PasswordPolicyStatusText.Foreground = System.Windows.Media.Brushes.LightCoral;
        }
    }

    private string FormatPasswordPolicyViolations(PasswordPolicyAnalysis analysis)
    {
        return string.Join(Environment.NewLine, analysis.Violations.Select(PasswordPolicyViolationText));
    }

    private string PasswordPolicyViolationText(PasswordPolicyViolation violation)
    {
        return violation switch
        {
            PasswordPolicyViolation.TooShort => string.Format(T("passwordViolationTooShort"), PasswordKeyService.MinPasswordLength),
            PasswordPolicyViolation.TooLong => string.Format(T("passwordViolationTooLong"), PasswordKeyService.MaxPasswordLength),
            PasswordPolicyViolation.ControlCharacter => T("passwordViolationControl"),
            PasswordPolicyViolation.InvalidUnicode => T("passwordViolationUnicode"),
            PasswordPolicyViolation.NotEnoughCharacterClasses => string.Format(T("passwordViolationClasses"), PasswordKeyService.MinPasswordCharacterClasses),
            PasswordPolicyViolation.NotEnoughDistinctCharacters => string.Format(T("passwordViolationDistinct"), PasswordKeyService.MinDistinctPasswordCharacters),
            PasswordPolicyViolation.NotEnoughNonHexCharacters => string.Format(T("passwordViolationNonHex"), PasswordKeyService.MinNonHexPasswordCharacters),
            PasswordPolicyViolation.HexadecimalRunTooLong => string.Format(T("passwordViolationHexRun"), PasswordKeyService.MaxHexadecimalRunLength),
            PasswordPolicyViolation.MatchesGeneratedPassword => T("passwordViolationMatchesGenerated"),
            PasswordPolicyViolation.InsufficientConservativeEntropy => string.Format(T("passwordViolationEntropy"), PasswordKeyService.MinimumConservativeEntropyBits.ToString("0", System.Globalization.CultureInfo.InvariantCulture)),
            _ => T("passwordComplexity"),
        };
    }

    internal void RefreshEntropyStatusForTests() => UpdateEntropyStatus();
    internal bool HasPreparedArchiveEntropyForTests =>
        _generatedArchiveEntropy is { HasPendingEncryptionParameters: true };

    internal DropTarget ResolveDropTargetFromElement(DependencyObject? source, IReadOnlyList<string> paths)
    {
        if (source is not null)
        {
            if (IsSelfOrDescendant(source, ArchivePathBox))
            {
                return DropTarget.TargetArchive;
            }

            if (IsSelfOrDescendant(source, ExtractArchiveBox))
            {
                return DropTarget.ExtractArchive;
            }

            if (IsSelfOrDescendant(source, OutputFolderBox))
            {
                return DropTarget.OutputFolder;
            }

            if (IsSelfOrDescendant(source, ErasePathBox) || IsSelfOrDescendant(source, ErasePanel))
            {
                return DropTarget.EraseTarget;
            }

            if (IsSelfOrDescendant(source, InputList) || IsSelfOrDescendant(source, CreatePanel))
            {
                return DropTarget.Inputs;
            }

            if (IsSelfOrDescendant(source, ExtractPanel))
            {
                if (paths.Any(IsArchiveCandidatePath))
                {
                    return DropTarget.ExtractArchive;
                }

                if (paths.Any(Directory.Exists))
                {
                    return DropTarget.OutputFolder;
                }
            }
        }

        return ResolveAutoDropTarget(paths);
    }

    internal DropResult ApplyDroppedPaths(IReadOnlyList<string> paths, DropTarget target)
    {
        if (paths.Count == 0 || Volatile.Read(ref _protectedOperationActive) != 0)
        {
            return DropResult.None;
        }

        DropTarget resolvedTarget = target == DropTarget.Auto ? ResolveAutoDropTarget(paths) : target;
        switch (resolvedTarget)
        {
            case DropTarget.Inputs:
                int added = AddInputPaths(paths);
                if (added > 0)
                {
                    SuggestArchiveTargetFromInputs(paths);
                    Log(string.Format(T("dropAddedInputs"), added));
                    return DropResult.InputsAdded;
                }

                return DropResult.None;

            case DropTarget.TargetArchive:
                int addedFromTargetDrop = AddInputFilesFromTargetDrop(paths);
                string targetArchive = ResolveArchiveTarget(paths[0]);
                ArchivePathBox.Text = targetArchive;
                ResetKeySheetStatus();
                if (addedFromTargetDrop > 0)
                {
                    Log(string.Format(T("dropAddedInputs"), addedFromTargetDrop));
                }

                Log(string.Format(T("dropTargetArchive"), targetArchive));
                return DropResult.TargetArchiveSet;

            case DropTarget.ExtractArchive:
                string? archive = paths.FirstOrDefault(IsArchiveCandidatePath);
                if (archive is null)
                {
                    return DropResult.None;
                }

                SetExtractArchivePath(archive);
                Log(string.Format(T("dropExtractArchive"), archive));
                return DropResult.ExtractArchiveSet;

            case DropTarget.OutputFolder:
                string? folder = paths.FirstOrDefault(Directory.Exists);
                if (folder is null)
                {
                    return DropResult.None;
                }

                OutputFolderBox.Text = folder;
                Log(string.Format(T("dropOutputFolder"), folder));
                return DropResult.OutputFolderSet;

            case DropTarget.EraseTarget:
                string? eraseTarget = paths.FirstOrDefault(File.Exists);
                if (eraseTarget is null)
                {
                    return DropResult.None;
                }

                SetErasePath(eraseTarget);
                Log(string.Format(T("dropEraseTarget"), eraseTarget));
                return DropResult.EraseTargetSet;

            default:
                return DropResult.None;
        }
    }

    private int AddInputPaths(IEnumerable<string> paths)
    {
        int added = 0;
        foreach (string path in paths.Where(path => File.Exists(path) || Directory.Exists(path)))
        {
            if (!InputList.Items.Contains(path))
            {
                InputList.Items.Add(path);
                added++;
            }
        }

        return added;
    }

    private int AddInputFilesFromTargetDrop(IReadOnlyList<string> paths)
    {
        return AddInputPaths(paths.Where(path => File.Exists(path) && !IsArchiveCandidatePath(path)));
    }

    private void HandleDrop(DragEventArgs e, DropTarget target)
    {
        string[] paths = GetDroppedPaths(e);
        DropResult result = ApplyDroppedPaths(paths, target);
        e.Effects = result == DropResult.None ? DragDropEffects.None : DragDropEffects.Copy;
        e.Handled = true;
    }

    private void SetDropEffect(DragEventArgs e, DropTarget target)
    {
        string[] paths = GetDroppedPaths(e);
        e.Effects = paths.Length > 0 && CanDrop(paths, target) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private bool CanDrop(IReadOnlyList<string> paths, DropTarget target)
    {
        if (paths.Count == 0)
        {
            return false;
        }

        DropTarget resolvedTarget = target == DropTarget.Auto ? ResolveAutoDropTarget(paths) : target;
        return resolvedTarget switch
        {
            DropTarget.Inputs => paths.Any(path => File.Exists(path) || Directory.Exists(path)),
            DropTarget.TargetArchive => paths.Count == 1,
            DropTarget.ExtractArchive => paths.Any(IsArchiveCandidatePath),
            DropTarget.OutputFolder => paths.Any(Directory.Exists),
            DropTarget.EraseTarget => paths.Any(File.Exists),
            _ => false,
        };
    }

    private DropTarget ResolveAutoDropTarget(IReadOnlyList<string> paths)
    {
        if (paths.Count == 1 && Directory.Exists(paths[0]))
        {
            return DropTarget.Inputs;
        }

        if (paths.Count == 1 && IsArchiveCandidatePath(paths[0]))
        {
            return DropTarget.ExtractArchive;
        }

        return DropTarget.Inputs;
    }

    internal string ResolveArchiveTarget(string path)
    {
        return SuggestTargetArchivePath(path, EncryptBox.IsChecked == true);
    }

    internal static string NormalizeTargetArchivePath(string path, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        string trimmed = path.Trim();
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(trimmed))
        {
            return Path.Combine(trimmed, $"archive{extension}");
        }

        string currentExtension = Path.GetExtension(trimmed);
        if (string.Equals(currentExtension, extension, StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        return Path.ChangeExtension(trimmed, extension);
    }

    internal static string SuggestTargetArchivePath(string path, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        string trimmed = path.Trim();
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(trimmed))
        {
            // Beside the folder, named after it — not inside it. An archive
            // created inside its own input is refused a moment later by the
            // safety check, so suggesting one only ever produced a dead end.
            string normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(trimmed));
            string? folderParent = Path.GetDirectoryName(normalized);
            string folderName = Path.GetFileName(normalized);
            return string.IsNullOrEmpty(folderParent) || string.IsNullOrWhiteSpace(folderName)
                ? BuildNumberedArchivePath(normalized, "archive", extension)
                : BuildNumberedArchivePath(folderParent, folderName, extension);
        }

        string directory = Path.GetDirectoryName(Path.GetFullPath(trimmed)) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(trimmed);
        if (string.IsNullOrWhiteSpace(stem))
        {
            stem = "archive";
        }

        return BuildNumberedArchivePath(directory, stem, extension);
    }

    internal void SetExtractArchivePath(string archivePath)
    {
        _suppressExtractArchiveTextChanged = true;
        try
        {
            ExtractArchiveBox.Text = archivePath;
        }
        finally
        {
            _suppressExtractArchiveTextChanged = false;
        }

        OutputFolderBox.Text = SuggestOutputFolderPath(archivePath);
        BeginExtractHintLoad(archivePath, debounce: false);
    }

    private void BeginExtractHintLoad(string archivePath, bool debounce)
    {
        int requestVersion = Interlocked.Increment(ref _extractHintLoadVersion);
        SetExtractHint(null, loaded: false);
        ExtractHintLoadTaskForTests = Task.CompletedTask;

        string path = archivePath.Trim();
        if (path.Length == 0 || !File.Exists(path) || _disposed)
        {
            return;
        }

        CancellationToken cancellationToken;
        try
        {
            cancellationToken = _shutdown.Token;
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        ExtractHintLoadTaskForTests = LoadExtractHintAsync(path, requestVersion, debounce, cancellationToken);
    }

    private async Task LoadExtractHintAsync(
        string archivePath,
        int requestVersion,
        bool debounce,
        CancellationToken cancellationToken)
    {
        string? hint = null;
        string? errorMessage = null;
        try
        {
            if (debounce)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
            }

            if (requestVersion != Volatile.Read(ref _extractHintLoadVersion))
            {
                return;
            }

            bool encrypted = await _kalyna.LooksEncryptedAsync(archivePath, cancellationToken).ConfigureAwait(false);
            if (encrypted)
            {
                KalynaContainerInfo info = await _kalyna.ReadContainerInfoAsync(archivePath, cancellationToken).ConfigureAwait(false);
                hint = info.Hint;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (IOException ex)
        {
            errorMessage = ex.Message;
        }
        catch (UnauthorizedAccessException ex)
        {
            errorMessage = ex.Message;
        }
        catch (CryptographicException ex)
        {
            errorMessage = ex.Message;
        }
        catch (ArgumentException ex)
        {
            errorMessage = ex.Message;
        }
        catch (NotSupportedException ex)
        {
            errorMessage = ex.Message;
        }
        catch (SecurityException ex)
        {
            errorMessage = ex.Message;
        }

        if (_disposed || requestVersion != Volatile.Read(ref _extractHintLoadVersion))
        {
            return;
        }

        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                if (_disposed
                    || requestVersion != Volatile.Read(ref _extractHintLoadVersion)
                    || !string.Equals(ExtractArchiveBox.Text.Trim(), archivePath, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (errorMessage is null)
                {
                    SetExtractHint(hint, loaded: true);
                    return;
                }

                SetExtractHintUnavailable();
                Log($"Container hint could not be loaded: {errorMessage}");
            }).Task.ConfigureAwait(false);
        }
        catch (TaskCanceledException) when (_disposed)
        {
        }
        catch (InvalidOperationException) when (_disposed || Dispatcher.HasShutdownStarted)
        {
        }
    }

    private void SetExtractHint(string? hint, bool loaded)
    {
        _extractHintLoaded = loaded;
        _extractHintUnavailable = false;
        _extractHint = string.IsNullOrWhiteSpace(hint) ? null : hint.Trim();
        RenderExtractHint();
    }

    private void SetExtractHintUnavailable()
    {
        _extractHintLoaded = false;
        _extractHintUnavailable = true;
        _extractHint = null;
        RenderExtractHint();
    }

    private void RenderExtractHint()
    {
        if (!_componentsReady)
        {
            return;
        }

        ExtractHintText.Text = _extractHintUnavailable
            ? T("extractHintUnavailable")
            : !_extractHintLoaded
            ? T("extractHintNotLoaded")
            : _extractHint is null
                ? T("extractHintNone")
                : string.Format(CultureInfo.CurrentCulture, T("extractHintUnverified"), _extractHint);
    }

    internal static string SuggestOutputFolderPath(string archivePath)
    {
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            return string.Empty;
        }

        string fullPath = Path.GetFullPath(archivePath.Trim());
        string directory = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(fullPath);
        if (string.IsNullOrWhiteSpace(stem))
        {
            stem = "extract";
        }

        return BuildNumberedDirectoryPath(directory, stem);
    }

    private void SuggestArchiveTargetFromInputs(IReadOnlyList<string> paths)
    {
        if (!string.IsNullOrWhiteSpace(ArchivePathBox.Text))
        {
            return;
        }

        string? firstInput = paths.FirstOrDefault(path => File.Exists(path) || Directory.Exists(path));
        if (firstInput is null)
        {
            return;
        }

        ArchivePathBox.Text = SuggestTargetArchivePath(firstInput, EncryptBox.IsChecked == true);
        ResetKeySheetStatus();
    }

    private static string BuildNumberedArchivePath(string directory, string stem, string extension)
    {
        int index = 1;
        string candidate;
        do
        {
            candidate = Path.Combine(directory, $"{stem}({index}){extension}");
            index++;
        }
        while (File.Exists(candidate) || Directory.Exists(candidate));

        return candidate;
    }

    private static string BuildNumberedDirectoryPath(string directory, string stem)
    {
        int index = 1;
        string candidate;
        do
        {
            candidate = Path.Combine(directory, $"{stem}({index})");
            index++;
        }
        while (Directory.Exists(candidate) || File.Exists(candidate));

        return candidate;
    }

    private void EnsureArchiveTargetIsSafe(string archivePath, IReadOnlyList<string> inputPaths)
    {
        string fullArchivePath = Path.GetFullPath(archivePath);
        if (File.Exists(fullArchivePath) || Directory.Exists(fullArchivePath))
        {
            throw new InvalidOperationException(T("archiveTargetExists"));
        }

        foreach (string inputPath in inputPaths)
        {
            string fullInputPath = Path.GetFullPath(inputPath);
            if (File.Exists(fullInputPath)
                && string.Equals(fullArchivePath, fullInputPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(T("archiveTargetOverwritesInput"));
            }

            if (Directory.Exists(fullInputPath) && IsPathInsideDirectory(fullArchivePath, fullInputPath))
            {
                throw new InvalidOperationException(T("archiveTargetInsideInput"));
            }
        }
    }

    private static bool IsPathInsideDirectory(string path, string directory)
    {
        string normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string normalizedDirectory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return normalizedPath.StartsWith(normalizedDirectory, StringComparison.OrdinalIgnoreCase);
    }

    private static string[] GetDroppedPaths(DragEventArgs e)
    {
        return e.Data.GetDataPresent(DataFormats.FileDrop)
            ? (string[])e.Data.GetData(DataFormats.FileDrop)
            : [];
    }

    private static bool IsArchiveCandidatePath(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        string extension = Path.GetExtension(path);
        if (string.Equals(extension, ".zpaq", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".kzpaq", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return HasKnownArchiveHeader(path);
    }

    private static bool HasKnownArchiveHeader(string path)
    {
        try
        {
            Span<byte> header = stackalloc byte[7];
            using FileStream stream = File.OpenRead(path);
            int read = stream.Read(header);
            return read >= 7 && header[..7].SequenceEqual("KZPAQ1\0"u8)
                || read >= 4 && header[..4].SequenceEqual("7kSt"u8)
                || read >= 3 && header[..3].SequenceEqual("zPQ"u8);
        }
        catch
        {
            return false;
        }
    }

    private DropTarget ResolveDropTargetFromEvent(DragEventArgs e, IReadOnlyList<string> paths)
    {
        return ResolveDropTargetFromElement(e.OriginalSource as DependencyObject, paths);
    }

    private static bool IsSelfOrDescendant(DependencyObject source, DependencyObject ancestor)
    {
        DependencyObject? current = source;
        while (current is not null)
        {
            if (ReferenceEquals(current, ancestor))
            {
                return true;
            }

            current = GetParent(current);
        }

        return false;
    }

    private static DependencyObject? GetParent(DependencyObject source)
    {
        if (source is FrameworkElement { Parent: DependencyObject parent })
        {
            return parent;
        }

        try
        {
            DependencyObject? visualParent = VisualTreeHelper.GetParent(source);
            if (visualParent is not null)
            {
                return visualParent;
            }
        }
        catch (InvalidOperationException)
        {
        }

        return LogicalTreeHelper.GetParent(source);
    }

    private void ApplyLanguage()
    {
        Title = T("windowTitle");
        TitleText.Text = T("title");
        SubtitleText.Text = T("subtitle");
        LanguageLabel.Text = T("language");
        ArchiveTab.Header = T("archiveTab");
        ExtractTab.Header = T("extractTab");
        EraseTab.Header = T("eraseTab");
        ApplyIntegrityStatusText();
        ApplyCaptureStatusText();
        CreateTitleText.Text = T("createTitle");
        CreateSubtitleText.Text = T("createSubtitle");
        AddFilesButton.Content = T("addFiles");
        AddFolderButton.Content = T("addFolder");
        ClearInputsButton.Content = T("clearSelection");
        InputDropHintText.Text = T("inputDropHint");
        TargetArchiveLabel.Text = T("targetArchive");
        TargetArchiveDropHintText.Text = T("targetArchiveDropHint");
        BrowseArchiveButton.Content = T("browse");
        CompressionLabel.Text = T("compression");
        EncryptBox.Content = T("encrypt");
        CipherSuiteLabel.Text = T("cipherSuite");
        Argon2ProfileText.Text = T("argon2Profile");
        CreateArchiveButton.Content = T("saveArchive");
        ExtractTitleText.Text = T("extractTitle");
        ExtractSubtitleText.Text = T("extractSubtitle");
        RecoveryPolicyText.Text = T("recoveryPolicy");
        ArchiveFileLabel.Text = T("archiveFile");
        ExtractArchiveDropHintText.Text = T("extractArchiveDropHint");
        BrowseExtractArchiveButton.Content = T("browse");
        OutputFolderLabel.Text = T("outputFolder");
        OutputFolderDropHintText.Text = T("outputFolderDropHint");
        BrowseOutputFolderButton.Content = T("browse");
        CreatePasswordSetupTitle.Text = T("createPasswordSetupTitle");
        CreatePasswordSetupHelpText.Text = T("createPasswordSetupHelp");
        PasswordGeneratorTitle.Text = T("passwordGeneratorTitle");
        PasswordGeneratorHelpText.Text = T("passwordGeneratorHelp");
        GeneratePasswordButton.Content = T("generatePassword");
        GeneratedPasswordFirstLabel.Text = T("generatedPasswordFirstLabel");
        GeneratedPasswordSecondLabel.Text = T("generatedPasswordSecondLabel");
        SaveKeySheetButton.Content = T("saveTestKeySheet");
        PrintKeySheetButton.Content = T("printKeySheet");
        ClearCreateSecretsButton.Content = T("clearSecrets");
        KeySheetStatusText.Text = _keySheetFingerprint is null ? T("keySheetMissing") : T("keySheetHandled");
        UpdateEntropyStatus();
        CreatePasswordLabel.Text = T("userPassword");
        CreatePasswordConfirmLabel.Text = T("userPasswordConfirm");
        HintLabel.Text = T("hint");
        HintWarningText.Text = T("hintWarning");
        PasswordHelpText.Text = T("passwordHelp");
        ExtractPasswordTitle.Text = T("extractPasswordTitle");
        ExtractPasswordHelpText.Text = T("extractPasswordHelp");
        ExtractHintLabel.Text = T("extractHintLabel");
        ExtractPasswordLabel.Text = T("userPassword");
        ExtractGeneratedPasswordFirstLabel.Text = T("extractGeneratedPasswordFirst");
        ExtractGeneratedPasswordSecondLabel.Text = T("extractGeneratedPasswordSecond");
        RenderExtractHint();
        UpdatePasswordPolicyStatus();
        ExtractArchiveButton.Content = T("extract");
        ListArchiveButton.Content = T("listContents");
        EmergencyRecoveryButton.Content = T("emergencyRecoveryButton");
        ClearExtractSecretsButton.Content = T("clearSecrets");
        EraseTitleText.Text = T("eraseTitle");
        EraseSubtitleText.Text = T("eraseSubtitle");
        EraseFileLabel.Text = T("eraseFile");
        EraseDropHintText.Text = T("eraseDropHint");
        BrowseEraseButton.Content = T("browse");
        AnalyzeEraseButton.Content = T("analyzeErase");
        if (EraseStatusText.Text is "No file analyzed yet." or "Noch keine Datei analysiert.")
        {
            EraseStatusText.Text = T("eraseNotAnalyzed");
        }

        EraseHardwareNoticeText.Text = T("eraseHardwareNotice");
        EraseConfirmBox.Content = T("eraseConfirm");
        EraseContainerButton.Content = T("eraseButton");
        LogTitleText.Text = T("log");
        ClearLogButton.Content = T("clear");
    }

    private string T(string key)
    {
        return (_language, key) switch
        {
            ("en", "windowTitle") => ProductInfo.Name,
            ("en", "title") => ProductInfo.Name,
            ("en", "subtitle") => "Create, extract, and cryptographically erase encrypted ZPAQ archives.",
            ("en", "language") => "Language",
            ("en", "archiveTab") => "Archive",
            ("en", "extractTab") => "Extract",
            ("en", "eraseTab") => "Cryptographic erase",
            ("en", "subtitle2") => "Create, extract, and cryptographically erase encrypted ZPAQ archives.",
            ("en", "createSubtitle") => "Select files or folders, choose the target archive, then print the two separately stored key sheets before encrypting.",
            ("en", "targetArchiveDropHint") => "Drop a folder here to create folder(1).kzpaq beside it, or drop any file to derive name(1).kzpaq.",
            ("en", "createPasswordSetupTitle") => "Three-part password for encrypted archives",
            ("en", "createPasswordSetupHelp") => "Extraction requires the user password plus two independently generated 512-bit hexadecimal passwords.",
            ("en", "passwordGeneratorTitle") => "Two independent generated 512-bit passwords",
            ("en", "passwordGeneratorHelp") => "Factor A, factor B, salt, nonce 1, and nonce 2 each require at least 512 different samples from evenly filled independent mouse pools. Generate creates all five outputs atomically and then securely consumes every pool; zero counters afterward mean used, not insufficient. Key = Argon2id(SHA3-512(UserPassword, A) || SHA3-512(UserPassword, B), Salt). Inputs are length-prefixed and domain-separated.",
            ("en", "entropyStatusCollecting") => "Collecting archive entropy: total {0}; factor A {1}/{7}; factor B {2}/{7}; salt {3}/{7}; nonce 1 {4}/{7}; nonce 2 {5}/{7}; nonce 3 {6}/{7}",
            ("en", "entropyStatusPrepared") => "Archive entropy ready: factors A/B, salt, and nonces were generated; their source samples were securely consumed. Fresh pools: total {0}; factor A {1}/{7}; factor B {2}/{7}; salt {3}/{7}; nonce 1 {4}/{7}; nonce 2 {5}/{7}; nonce 3 {6}/{7}",
            ("en", "entropyStatusRetry") => "Factors A/B remain valid because their source entropy was already consumed. Fresh salt/nonces are required only for a retry: total {0}; factor A {1}/{7}; factor B {2}/{7}; salt {3}/{7}; nonce 1 {4}/{7}; nonce 2 {5}/{7}; nonce 3 {6}/{7}",
            ("en", "entropyGeneratedPasswordFirst") => "generated password A",
            ("en", "entropyGeneratedPasswordSecond") => "generated password B",
            ("en", "entropySalt") => "salt",
            ("en", "entropyNonceFirst") => "nonce 1",
            ("en", "entropyNonceSecond") => "nonce 2",
            ("en", "entropyNonceThird") => "nonce 3",
            ("en", "entropyNotReady") => "Not enough mouse entropy samples for {0}. Required: {1}; current: {2}; missing: {3}. Move the mouse over the app window and try again.",
            ("en", "generatePassword") => "Generate",
            ("en", "regeneratePassword") => "Regenerate",
            ("en", "generatedPasswordFirstLabel") => "Generated password A",
            ("en", "generatedPasswordSecondLabel") => "Generated password B",
            ("en", "userPassword") => "User password",
            ("en", "userPasswordConfirm") => "Repeat user password",
            ("en", "passwordHelp") => "User password: 24-128 characters, at least 3 character groups, 12 distinct characters, 12 non-hexadecimal characters, no hexadecimal run of 8+, and a conservative score of at least 128 bits. It must differ from both generated factors.",
            ("en", "passwordEntropyStatus") => "Conservative entropy score: {0} / {1} bits",
            ("en", "passwordPolicyAccepted") => "All user-password requirements are met.",
            ("en", "passwordViolationTooShort") => "Use at least {0} characters.",
            ("en", "passwordViolationTooLong") => "Use no more than {0} characters.",
            ("en", "passwordViolationControl") => "Remove control characters.",
            ("en", "passwordViolationUnicode") => "Remove malformed Unicode characters.",
            ("en", "passwordViolationClasses") => "Use at least {0} groups: uppercase, lowercase, digits, symbols.",
            ("en", "passwordViolationDistinct") => "Use at least {0} different characters.",
            ("en", "passwordViolationNonHex") => "Use at least {0} characters outside 0-9 and A-F/a-f.",
            ("en", "passwordViolationHexRun") => "Break every hexadecimal-only run after at most {0} characters.",
            ("en", "passwordViolationMatchesGenerated") => "Do not reuse either generated 512-bit factor as the user password.",
            ("en", "passwordViolationEntropy") => "Increase unique, non-pattern characters until the conservative score reaches {0} bits.",
            ("en", "extractPasswordHelp") => "Enter the user password and both generated hexadecimal passwords from the separately stored key sheets.",
            ("en", "extractGeneratedPasswordFirst") => "Generated password A from key sheet",
            ("en", "extractGeneratedPasswordSecond") => "Generated password B from key sheet",
            ("en", "saveTestKeySheet") => "Save test PDF",
            ("en", "printKeySheet") => "Print separate key sheets",
            ("en", "keySheetMissing") => "The two key sheets have not been printed or explicitly exported for testing yet.",
            ("en", "keySheetHandled") => "Separate key sheets were printed or explicitly exported for testing for the current archive and factors.",
            ("en", "keySheetRequired") => "Print the separate key sheets (recommended), or explicitly save a test PDF, before creating the encrypted archive.",
            ("en", "keySheetTestPdfSavedLog") => "Test key-sheet PDF saved to persistent storage: {0}",
            ("en", "keySheetPrintedLog") => "Key sheets sent to a physical printer without an app-created PDF. The Windows print spooler and driver remain outside the app's storage control.",
            ("en", "saveTestKeySheetDialog") => "Save test key-sheet PDF (writes secrets to disk)",
            ("en", "pdfFilter") => "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*",
            ("en", "generatedPasswordLength") => "The generated password must contain exactly 128 hexadecimal characters.",
            ("en", "passwordComplexity") => "The user password does not meet the required security policy.",
            ("en", "passwordMatchesGenerated") => "The user password must not equal either generated 512-bit password.",
            ("en", "chooseEraseDialog") => "Select encrypted container for cryptographic erase",
            ("en", "eraseTitle") => "Cryptographic erase",
            ("en", "eraseSubtitle") => "Erase encrypted containers by corrupting and deleting the encrypted container. Plain files require drive-level secure erase.",
            ("en", "eraseFile") => "Encrypted container",
            ("en", "eraseDropHint") => "Drop an encrypted .kzpaq container here.",
            ("en", "eraseNotAnalyzed") => "No file analyzed yet.",
            ("en", "eraseHardwareNotice") => "Hardware SSD secure erase is whole-drive vendor/firmware functionality, not a per-file app operation.",
            ("en", "eraseConfirm") => "I understand that per-file hardware secure erase on SSDs cannot be guaranteed and I want to delete this encrypted container.",
            ("en", "eraseButton") => "Cryptographically erase container",
            ("en", "analyzeErase") => "Analyze",
            ("en", "eraseMissing") => "Please select an encrypted container first.",
            ("en", "eraseConfirmMissing") => "Please confirm the SSD/hardware erase limitation before deleting.",
            ("en", "eraseFinalConfirm") => "This will corrupt and delete the selected encrypted container. Continue?",
            ("en", "dropEraseTarget") => "Cryptographic erase target set from drop: {0}",
            ("en", "generatedPasswordLog") => "Generated two independent 512-bit hexadecimal factors and prepared a fresh salt and nonce in locked RAM. Print the separate key sheets before encrypting.",
            ("en", "integrityChecking") => "Checking integrity ...",
            ("en", "captureActivating") => "Screen capture protection: enabling ...",
            ("en", "captureActive") => "Screen capture protection: active",
            ("en", "captureUnavailable") => "Screen capture protection: unavailable",
            ("en", "createTitle") => "Create Archive",
            ("en", "addFiles") => "Add files",
            ("en", "addFolder") => "Add folder",
            ("en", "clearSelection") => "Clear selection",
            ("en", "inputDropHint") => "Drop files or folders anywhere in this panel to add them.",
            ("en", "targetArchive") => "Target archive",
            ("en", "browse") => "Browse",
            ("en", "compression") => "Compression",
            ("en", "encrypt") => "Encrypt archive",
            ("en", "cipherSuite") => "Cipher suite",
            ("en", "argon2Profile") => "Argon2id: 1 GiB memory, 4 iterations, parallelism 4 (locked RAM required)",
            ("en", "cipherSuiteSelected") => "Cipher suite selected: {0}",
            ("en", "selectedSuiteMissing") => "The signed and manifest-verified reference library for {0} is unavailable.",
            ("en", "saveArchive") => "Save archive",
            ("en", "extractTitle") => "Extract",
            ("en", "extractSubtitle") => "Select a ZPAQ file or encrypted ZPAQ container and choose the output folder.",
            ("en", "recoveryPolicy") => "KPAR2 authenticates encrypted archives with HMAC-SHA3-512 and Skein-1024 MAC. For unencrypted archives it provides error correction only. Emergency recovery always writes a new file.",
            ("en", "archiveFile") => "Archive file",
            ("en", "extractArchiveDropHint") => "Drop a .zpaq or .kzpaq file here, or anywhere in this panel.",
            ("en", "outputFolder") => "Output folder",
            ("en", "outputFolderDropHint") => "Suggested automatically from the archive name. Drop a folder here to override it.",
            ("en", "password") => "Password",
            ("en", "passwordConfirm") => "Repeat password",
            ("en", "hint") => "Optional hint",
            ("en", "hintWarning") => "Stored in the public container header. Do not enter passwords or secret fragments.",
            ("en", "extractHintLabel") => "Optional hint from archive",
            ("en", "extractHintNotLoaded") => "No container hint loaded.",
            ("en", "extractHintNone") => "The container has no password hint.",
            ("en", "extractHintUnverified") => "Unverified public header hint: {0}",
            ("en", "extractHintUnavailable") => "The public hint could not be read from this archive.",
            ("en", "extractPasswordTitle") => "Password for extraction",
            ("en", "extract") => "Extract",
            ("en", "listContents") => "Show contents",
            ("en", "emergencyRecoveryButton") => "Emergency recovery to new file",
            ("en", "emergencyRecoveryTitle") => "Unauthenticated emergency recovery",
            ("en", "emergencyRecoveryMissing") => "No valid KPAR2 v2 recovery file was found for this archive.",
            ("en", "emergencyRecoveryEncryptedWarning") => "Emergency mode skips KPAR2 metadata authentication and never modifies the original. It writes a new file and still requires all password factors plus successful SHA3-512/Skein-1024 container authentication. Continue?",
            ("en", "emergencyRecoveryPlainWarning") => "This unencrypted KPAR2 profile provides error correction only, not protection against malicious changes. Emergency mode never modifies the original and writes a new file. Continue?",
            ("en", "encryptedHeaderWithoutRecovery") => "This .kzpaq file has no valid encrypted-container header and no usable KPAR2 recovery file. It is blocked instead of being treated as an unencrypted ZPAQ archive.",
            ("en", "recoveryNewFile") => "Recovery output selected: {0}",
            ("en", "log") => "Log",
            ("en", "clear") => "Clear",
            ("en", "notFound") => "not found",
            ("en", "kalynaAvailable") => "Kalyna reference library: available",
            ("en", "kalynaMissing") => "Kalyna reference library: missing (encryption is blocked)",
            ("en", "threefishAvailable") => "Threefish reference library: available",
            ("en", "threefishMissing") => "Threefish reference library: missing (Threefish encryption is blocked)",
            ("en", "chooseFilesDialog") => "Select files for ZPAQ",
            ("en", "chooseFolderDialog") => "Select folder for ZPAQ",
            ("en", "saveArchiveDialog") => "Save target archive",
            ("en", "chooseArchiveDialog") => "Select archive",
            ("en", "chooseOutputDialog") => "Select output folder",
            ("en", "kalynaFilter") => "Encrypted ZPAQ Container (*.kzpaq)|*.kzpaq|All files (*.*)|*.*",
            ("en", "zpaqFilter") => "ZPAQ Archives (*.zpaq)|*.zpaq|All files (*.*)|*.*",
            ("en", "archiveFilter") => "Archives (*.zpaq;*.kzpaq)|*.zpaq;*.kzpaq|All files (*.*)|*.*",
            ("en", "missingInputTitle") => "Missing input",
            ("en", "targetMissingTitle") => "Missing target",
            ("en", "errorTitle") => "Error",
            ("en", "doneTitle") => "Done",
            ("en", "inputsMissing") => "Please select at least one file or folder.",
            ("en", "targetMissing") => "Please select a target archive.",
            ("en", "archiveTargetOverwritesInput") => "The target archive would overwrite one of the selected input files. Please choose a .zpaq or .kzpaq target path.",
            ("en", "archiveTargetInsideInput") => "The target archive must not be created inside a selected input folder.",
            ("en", "archiveTargetExists") => "The target archive already exists. Choose a new numbered target path.",
            ("en", "creatingZpaq") => "Creating ZPAQ archive ...",
            ("en", "zpaqCreateFailed") => "ZPAQ could not create the archive.",
            ("en", "encrypting") => "Encrypting ZPAQ archive ...",
            ("en", "encryptingStreaming") => "Creating ZPAQ stream and encrypting directly in RAM with {0} ...",
            ("en", "archiveCreated") => "The archive was created.",
            ("en", "extractInputMissing") => "Please select an archive file and output folder.",
            ("en", "extracting") => "Extracting archive ...",
            ("en", "extractingStreaming") => "Authenticating and decrypting the encrypted container directly into the ZPAQ extractor pipe ...",
            ("en", "retryAfterRecovery") => "Encrypted container was repaired; retrying authentication and decryption once.",
            ("en", "zpaqExtractFailed") => "ZPAQ could not extract the archive.",
            ("en", "archiveExtracted") => "The archive was extracted.",
            ("en", "archiveMissing") => "Please select an archive file.",
            ("en", "passwordMismatch") => "The two password entries do not match.",
            ("en", "passwordLength") => "The password must be 24 to 128 characters long.",
            ("en", "integrityNoManifest") => "SHA3-512/Skein-1024 dual manifest missing.",
            ("en", "integrityOk") => "Integrity check passed.",
            ("en", "integrityWarning") => "WARNING: Application integrity violated.",
            ("en", "integrityFailed") => "Integrity check failed.",
            ("en", "dropAddedInputs") => "Added {0} dropped item(s).",
            ("en", "dropTargetArchive") => "Target archive set from drop: {0}",
            ("en", "dropExtractArchive") => "Extract archive set from drop: {0}",
            ("en", "dropOutputFolder") => "Output folder set from drop: {0}",
            ("en", "generatedPasswordClearedLog") => "Cleared generated password fields.",
            ("en", "clearSecrets") => "Clear secrets",

            (_, "windowTitle") => ProductInfo.Name,
            (_, "title") => ProductInfo.Name,
            (_, "subtitle") => "Verschlüsselte ZPAQ-Archive erstellen, entpacken und kryptografisch löschen.",
            (_, "language") => "Sprache",
            (_, "archiveTab") => "Archivierung",
            (_, "extractTab") => "Entpacken",
            (_, "eraseTab") => "Cryptographic erase",
            (_, "subtitle2") => "Verschlüsselte ZPAQ-Archive erstellen, entpacken und kryptografisch löschen.",
            (_, "createSubtitle") => "Dateien oder Ordner auswählen, Zielarchiv festlegen und vor der Verschlüsselung die zwei getrennten Schlüsselzettel drucken.",
            (_, "targetArchiveDropHint") => "Ordner hier ablegen, um daneben ordner(1).kzpaq zu erstellen, oder eine Datei als Namensvorlage für name(1).kzpaq ablegen.",
            (_, "createPasswordSetupTitle") => "Dreiteiliges Passwort für verschlüsselte Archive",
            (_, "createPasswordSetupHelp") => "Zum Entpacken werden das Userpasswort sowie zwei unabhängig generierte 512-Bit-Hex-Passwörter benötigt.",
            (_, "passwordGeneratorTitle") => "Zwei unabhängige generierte 512-Bit-Passwörter",
            (_, "passwordGeneratorHelp") => "Faktor A, Faktor B, Salt, Nonce 1 und Nonce 2 benötigen jeweils mindestens 512 verschiedene Samples aus gleichmäßig gefüllten, getrennten Mauspools. Generieren erzeugt alle fünf Ausgaben atomar und verbraucht danach jeden Pool sicher; Zähler null bedeutet anschließend verbraucht, nicht unzureichend. Schlüssel = Argon2id(SHA3-512(Userpasswort, A) || SHA3-512(Userpasswort, B), Salt). Die Eingaben werden längencodiert und domänengetrennt.",
            (_, "entropyStatusCollecting") => "Archiv-Entropie wird gesammelt: gesamt {0}; Faktor A {1}/{7}; Faktor B {2}/{7}; Salt {3}/{7}; Nonce 1 {4}/{7}; Nonce 2 {5}/{7}; Nonce 3 {6}/{7}",
            (_, "entropyStatusPrepared") => "Archiv-Entropie bereit: Faktoren A/B, Salt und Nonces wurden erzeugt; ihre Quell-Samples sind sicher verbraucht. Frische Pools: gesamt {0}; Faktor A {1}/{7}; Faktor B {2}/{7}; Salt {3}/{7}; Nonce 1 {4}/{7}; Nonce 2 {5}/{7}; Nonce 3 {6}/{7}",
            (_, "entropyStatusRetry") => "Faktoren A/B bleiben gültig, da ihre Quell-Entropie bereits verbraucht wurde. Nur für einen Wiederholungsversuch werden frischer Salt und frische Nonces benötigt: gesamt {0}; Faktor A {1}/{7}; Faktor B {2}/{7}; Salt {3}/{7}; Nonce 1 {4}/{7}; Nonce 2 {5}/{7}; Nonce 3 {6}/{7}",
            (_, "entropyGeneratedPasswordFirst") => "generiertes Passwort A",
            (_, "entropyGeneratedPasswordSecond") => "generiertes Passwort B",
            (_, "entropySalt") => "Salt",
            (_, "entropyNonceFirst") => "Nonce 1",
            (_, "entropyNonceSecond") => "Nonce 2",
            (_, "entropyNonceThird") => "Nonce 3",
            (_, "entropyNotReady") => "Nicht genug Maus-Entropie-Samples für {0}. Erforderlich: {1}; aktuell: {2}; fehlend: {3}. Bewege die Maus über dem App-Fenster und versuche es erneut.",
            (_, "generatePassword") => "Generieren",
            (_, "regeneratePassword") => "Neu generieren",
            (_, "generatedPasswordFirstLabel") => "Generiertes Passwort A",
            (_, "generatedPasswordSecondLabel") => "Generiertes Passwort B",
            (_, "userPassword") => "Userpasswort",
            (_, "userPasswordConfirm") => "Userpasswort wiederholen",
            (_, "passwordHelp") => "Userpasswort: 24-128 Zeichen, mindestens 3 Zeichengruppen, 12 verschiedene Zeichen, 12 Nicht-Hex-Zeichen, keine Hex-Folge ab 8 Zeichen und mindestens 128 Bit konservative Bewertung. Es muss von beiden generierten Faktoren verschieden sein.",
            (_, "passwordEntropyStatus") => "Konservative Entropiebewertung: {0} / {1} Bit",
            (_, "passwordPolicyAccepted") => "Alle Anforderungen an das Userpasswort sind erfüllt.",
            (_, "passwordViolationTooShort") => "Mindestens {0} Zeichen verwenden.",
            (_, "passwordViolationTooLong") => "Höchstens {0} Zeichen verwenden.",
            (_, "passwordViolationControl") => "Steuerzeichen entfernen.",
            (_, "passwordViolationUnicode") => "Ungültige Unicode-Zeichen entfernen.",
            (_, "passwordViolationClasses") => "Mindestens {0} Gruppen verwenden: Großbuchstaben, Kleinbuchstaben, Ziffern, Sonderzeichen.",
            (_, "passwordViolationDistinct") => "Mindestens {0} verschiedene Zeichen verwenden.",
            (_, "passwordViolationNonHex") => "Mindestens {0} Zeichen außerhalb von 0-9 und A-F/a-f verwenden.",
            (_, "passwordViolationHexRun") => "Jede reine Hex-Folge spätestens nach {0} Zeichen unterbrechen.",
            (_, "passwordViolationMatchesGenerated") => "Keinen der generierten 512-Bit-Faktoren als Userpasswort wiederverwenden.",
            (_, "passwordViolationEntropy") => "Mehr eindeutige, nicht schematische Zeichen verwenden, bis die konservative Bewertung {0} Bit erreicht.",
            (_, "extractPasswordHelp") => "Userpasswort und beide generierten Hex-Passwörter von den getrennt gelagerten Schlüsselzetteln eingeben.",
            (_, "extractGeneratedPasswordFirst") => "Generiertes Passwort A vom Schlüsselzettel",
            (_, "extractGeneratedPasswordSecond") => "Generiertes Passwort B vom Schlüsselzettel",
            (_, "saveTestKeySheet") => "Test-PDF speichern",
            (_, "printKeySheet") => "Getrennte Schlüsselzettel drucken",
            (_, "keySheetMissing") => "Die zwei Schlüsselzettel wurden noch nicht gedruckt oder ausdrücklich als Test exportiert.",
            (_, "keySheetHandled") => "Getrennte Schlüsselzettel wurden für das aktuelle Archiv und die Faktoren gedruckt oder ausdrücklich als Test exportiert.",
            (_, "keySheetRequired") => "Die getrennten Schlüsselzettel vor dem Erstellen drucken (empfohlen) oder ausdrücklich eine Test-PDF speichern.",
            (_, "keySheetTestPdfSavedLog") => "Test-Schlüsselzettel-PDF im permanenten Speicher abgelegt: {0}",
            (_, "keySheetPrintedLog") => "Schlüsselzettel ohne von der App erzeugte PDF an einen physischen Drucker gesendet. Windows-Druckspooler und Treiber liegen außerhalb der Speicherkontrolle der App.",
            (_, "saveTestKeySheetDialog") => "Test-Schlüsselzettel-PDF speichern (schreibt Geheimnisse auf die Festplatte)",
            (_, "pdfFilter") => "PDF-Dateien (*.pdf)|*.pdf|Alle Dateien (*.*)|*.*",
            (_, "generatedPasswordLength") => "Das generierte Passwort muss exakt 128 Hexadezimalzeichen enthalten.",
            (_, "passwordComplexity") => "Das Userpasswort erfüllt die Sicherheitsrichtlinie nicht.",
            (_, "passwordMatchesGenerated") => "Das Userpasswort darf keinem der generierten 512-Bit-Passwörter entsprechen.",
            (_, "chooseEraseDialog") => "Verschlüsselten Container für Cryptographic erase auswählen",
            (_, "eraseTitle") => "Cryptographic erase",
            (_, "eraseSubtitle") => "Verschlüsselte Container durch Beschädigen und Löschen des Containers entfernen. Unverschlüsselte Dateien benötigen eine Laufwerks-/Hardware-Löschung.",
            (_, "eraseFile") => "Verschlüsselter Container",
            (_, "eraseDropHint") => "Verschlüsselten .kzpaq-Container hier ablegen.",
            (_, "eraseNotAnalyzed") => "Noch keine Datei analysiert.",
            (_, "eraseHardwareNotice") => "Hardwarebasierte SSD-Löschung ist eine laufwerksweite Hersteller-/Firmware-Funktion, keine per-Datei-App-Operation.",
            (_, "eraseConfirm") => "Ich verstehe, dass per-Datei-Hardware-Löschung auf SSDs nicht garantiert werden kann, und möchte diesen verschlüsselten Container löschen.",
            (_, "eraseButton") => "Container kryptografisch löschen",
            (_, "analyzeErase") => "Analysieren",
            (_, "eraseMissing") => "Bitte zuerst einen verschlüsselten Container auswählen.",
            (_, "eraseConfirmMissing") => "Bitte bestätige die SSD-/Hardware-Löschgrenze vor dem Löschen.",
            (_, "eraseFinalConfirm") => "Der ausgewählte verschlüsselte Container wird beschädigt und gelöscht. Fortfahren?",
            (_, "dropEraseTarget") => "Cryptographic-erase-Ziel per Drag-and-Drop gesetzt: {0}",
            (_, "generatedPasswordLog") => "Zwei unabhängige 512-Bit-Hex-Faktoren erzeugt sowie frischen Salt und frische Nonce im gesperrten RAM vorbereitet. Vor dem Verschlüsseln die getrennten Schlüsselzettel drucken.",
            (_, "integrityChecking") => "Integrität wird geprüft ...",
            (_, "captureActivating") => "Bildschirmaufnahme-Schutz: wird aktiviert ...",
            (_, "captureActive") => "Bildschirmaufnahme-Schutz: aktiv",
            (_, "captureUnavailable") => "Bildschirmaufnahme-Schutz: nicht verfügbar",
            (_, "createTitle") => "Archiv erstellen",
            (_, "addFiles") => "Dateien hinzufügen",
            (_, "addFolder") => "Ordner hinzufügen",
            (_, "clearSelection") => "Auswahl leeren",
            (_, "inputDropHint") => "Dateien oder Ordner irgendwo in dieses Panel ziehen, um sie hinzuzufügen.",
            (_, "targetArchive") => "Zielarchiv",
            (_, "browse") => "Durchsuchen",
            (_, "compression") => "Kompression",
            (_, "encrypt") => "Archiv verschlüsseln",
            (_, "cipherSuite") => "Verschlüsselungsverfahren",
            (_, "argon2Profile") => "Argon2id: 1 GiB Speicher, 4 Iterationen, Parallelität 4 (gesperrter RAM erforderlich)",
            (_, "cipherSuiteSelected") => "Verschlüsselungsverfahren gewählt: {0}",
            (_, "selectedSuiteMissing") => "Die signierte und manifestgeprüfte Referenzbibliothek für {0} ist nicht verfügbar.",
            (_, "saveArchive") => "Archiv speichern",
            (_, "extractTitle") => "Entpacken",
            (_, "extractSubtitle") => "ZPAQ-Datei oder verschlüsselten ZPAQ-Container auswählen und Zielordner festlegen.",
            (_, "recoveryPolicy") => "KPAR2 authentifiziert verschlüsselte Archive mit HMAC-SHA3-512 und Skein-1024-MAC. Für unverschlüsselte Archive bietet es ausschließlich Fehlerkorrektur. Die Notfallwiederherstellung schreibt immer eine neue Datei.",
            (_, "archiveFile") => "Archivdatei",
            (_, "extractArchiveDropHint") => ".zpaq- oder .kzpaq-Datei hier oder irgendwo in dieses Panel ziehen.",
            (_, "outputFolder") => "Zielordner",
            (_, "outputFolderDropHint") => "Wird automatisch aus dem Archivnamen vorgeschlagen. Ordner hier ablegen, um ihn zu überschreiben.",
            (_, "password") => "Passwort",
            (_, "passwordConfirm") => "Passwort wiederholen",
            (_, "hint") => "Optionaler Hinweis",
            (_, "hintWarning") => "Wird im öffentlichen Containerkopf gespeichert. Keine Passwörter oder geheimen Fragmente eintragen.",
            (_, "extractHintLabel") => "Optionaler Hinweis aus dem Archiv",
            (_, "extractHintNotLoaded") => "Noch kein Containerhinweis geladen.",
            (_, "extractHintNone") => "Der Container enthält keinen Passworthinweis.",
            (_, "extractHintUnverified") => "Unbestätigter öffentlicher Kopf-Hinweis: {0}",
            (_, "extractHintUnavailable") => "Der öffentliche Hinweis konnte aus diesem Archiv nicht gelesen werden.",
            (_, "extractPasswordTitle") => "Passwort zum Entpacken",
            (_, "extract") => "Entpacken",
            (_, "listContents") => "Inhalt anzeigen",
            (_, "emergencyRecoveryButton") => "Notfallwiederherstellung in neue Datei",
            (_, "emergencyRecoveryTitle") => "Nicht authentifizierte Notfallwiederherstellung",
            (_, "emergencyRecoveryMissing") => "Für dieses Archiv wurde keine gültige KPAR2-v2-Wiederherstellungsdatei gefunden.",
            (_, "emergencyRecoveryEncryptedWarning") => "Der Notfallmodus überspringt die KPAR2-Metadaten-Authentifizierung und verändert niemals das Original. Er schreibt eine neue Datei und verlangt weiterhin alle Passwortfaktoren sowie eine erfolgreiche SHA3-512-/Skein-1024-Container-Authentifizierung. Fortfahren?",
            (_, "emergencyRecoveryPlainWarning") => "Dieses unverschlüsselte KPAR2-Profil bietet nur Fehlerkorrektur und keinen Schutz gegen absichtliche Änderungen. Der Notfallmodus verändert niemals das Original und schreibt eine neue Datei. Fortfahren?",
            (_, "encryptedHeaderWithoutRecovery") => "Diese .kzpaq-Datei besitzt keinen gültigen Kopf eines verschlüsselten Containers und keine nutzbare KPAR2-Wiederherstellungsdatei. Sie wird blockiert, statt als unverschlüsseltes ZPAQ-Archiv behandelt zu werden.",
            (_, "recoveryNewFile") => "Wiederherstellungsdatei ausgewählt: {0}",
            (_, "log") => "Protokoll",
            (_, "clear") => "Leeren",
            (_, "notFound") => "nicht gefunden",
            (_, "kalynaAvailable") => "Kalyna-Referenzbibliothek: verfügbar",
            (_, "kalynaMissing") => "Kalyna-Referenzbibliothek: fehlt (Verschlüsselung wird blockiert)",
            (_, "threefishAvailable") => "Threefish-Referenzbibliothek: verfügbar",
            (_, "threefishMissing") => "Threefish-Referenzbibliothek: fehlt (Threefish-Verschlüsselung wird blockiert)",
            (_, "chooseFilesDialog") => "Dateien für ZPAQ auswählen",
            (_, "chooseFolderDialog") => "Ordner für ZPAQ auswählen",
            (_, "saveArchiveDialog") => "Zielarchiv speichern",
            (_, "chooseArchiveDialog") => "Archiv auswählen",
            (_, "chooseOutputDialog") => "Zielordner auswählen",
            (_, "kalynaFilter") => "Verschlüsselter ZPAQ-Container (*.kzpaq)|*.kzpaq|Alle Dateien (*.*)|*.*",
            (_, "zpaqFilter") => "ZPAQ Archive (*.zpaq)|*.zpaq|Alle Dateien (*.*)|*.*",
            (_, "archiveFilter") => "Archive (*.zpaq;*.kzpaq)|*.zpaq;*.kzpaq|Alle Dateien (*.*)|*.*",
            (_, "missingInputTitle") => "Eingabe fehlt",
            (_, "targetMissingTitle") => "Ziel fehlt",
            (_, "errorTitle") => "Fehler",
            (_, "doneTitle") => "Fertig",
            (_, "inputsMissing") => "Bitte mindestens eine Datei oder einen Ordner auswählen.",
            (_, "targetMissing") => "Bitte ein Zielarchiv auswählen.",
            (_, "archiveTargetOverwritesInput") => "Das Zielarchiv würde eine ausgewählte Eingabedatei überschreiben. Bitte einen .zpaq- oder .kzpaq-Zielpfad wählen.",
            (_, "archiveTargetInsideInput") => "Das Zielarchiv darf nicht innerhalb eines ausgewählten Eingabeordners erstellt werden.",
            (_, "archiveTargetExists") => "Das Zielarchiv existiert bereits. Bitte einen neuen nummerierten Zielpfad wählen.",
            (_, "creatingZpaq") => "Erstelle ZPAQ-Archiv ...",
            (_, "zpaqCreateFailed") => "ZPAQ konnte das Archiv nicht erstellen.",
            (_, "encrypting") => "Verschlüssele ZPAQ-Archiv ...",
            (_, "encryptingStreaming") => "Erzeuge ZPAQ-Stream und verschlüssele direkt im RAM mit {0} ...",
            (_, "archiveCreated") => "Archiv wurde erstellt.",
            (_, "extractInputMissing") => "Bitte Archivdatei und Zielordner auswählen.",
            (_, "extracting") => "Entpacke Archiv ...",
            (_, "extractingStreaming") => "Authentifiziere und entschlüssele den Container direkt in die ZPAQ-Entpacker-Pipe ...",
            (_, "retryAfterRecovery") => "Verschlüsselter Container wurde repariert; Authentifizierung und Entschlüsselung werden einmal wiederholt.",
            (_, "zpaqExtractFailed") => "ZPAQ konnte das Archiv nicht entpacken.",
            (_, "archiveExtracted") => "Archiv wurde entpackt.",
            (_, "archiveMissing") => "Bitte eine Archivdatei auswählen.",
            (_, "passwordMismatch") => "Die beiden Passwort-Eingaben stimmen nicht überein.",
            (_, "passwordLength") => "Das Passwort muss 24 bis 128 Zeichen lang sein.",
            (_, "integrityNoManifest") => "SHA3-512-/Skein-1024-Dualmanifest fehlt.",
            (_, "integrityOk") => "Integritätsprüfung bestanden.",
            (_, "integrityWarning") => "WARNUNG: Programmintegrität verletzt.",
            (_, "integrityFailed") => "Integritätsprüfung fehlgeschlagen.",
            (_, "dropAddedInputs") => "{0} abgelegte Elemente hinzugefügt.",
            (_, "dropTargetArchive") => "Zielarchiv per Drag-and-Drop gesetzt: {0}",
            (_, "dropExtractArchive") => "Entpack-Archiv per Drag-and-Drop gesetzt: {0}",
            (_, "dropOutputFolder") => "Zielordner per Drag-and-Drop gesetzt: {0}",
            (_, "generatedPasswordClearedLog") => "Generierte Passwortfelder geleert.",
            (_, "clearSecrets") => "Geheimwerte leeren",
            _ => key,
        };
    }

    private string LoadSavedLanguage()
    {
        string? value = _settingsStore.Read(LanguageSettingsFile)?.Trim();
        return value is "de" or "en" ? value : "en";
    }

    private void SaveLanguage(string language)
    {
        if (language is not ("de" or "en"))
        {
            return;
        }

        _settingsStore.Write(LanguageSettingsFile, language);
    }

    private void SelectLanguageItem(string language)
    {
        foreach (object item in LanguageBox.Items)
        {
            if (item is System.Windows.Controls.ComboBoxItem comboBoxItem && Equals(comboBoxItem.Tag, language))
            {
                LanguageBox.SelectedItem = comboBoxItem;
                return;
            }
        }

        LanguageBox.SelectedIndex = 1;
    }

    private EncryptionSuite LoadSavedCipherSuite()
    {
        string? value = _settingsStore.Read(CipherSuiteSettingsFile)?.Trim();
        return Enum.TryParse(value, ignoreCase: false, out EncryptionSuite suite) && Enum.IsDefined(suite)
            ? suite
            : EncryptionSuiteCatalog.Default;
    }

    private void SaveCipherSuite(EncryptionSuite suite)
    {
        if (!Enum.IsDefined(suite))
        {
            return;
        }

        _settingsStore.Write(CipherSuiteSettingsFile, suite.ToString());
    }

    private int LoadSavedCompressionLevel()
    {
        string? value = _settingsStore.Read(CompressionSettingsFile)?.Trim();
        return int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int level)
            && level is >= 0 and <= MaxCompressionLevel
            ? level
            : DefaultCompressionLevel;
    }

    private void SaveCompressionLevel(int level)
    {
        if (level is < 0 or > MaxCompressionLevel)
        {
            return;
        }

        _settingsStore.Write(CompressionSettingsFile, level.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private void SelectCipherSuiteItem(EncryptionSuite suite)
    {
        string tag = suite.ToString();
        foreach (object item in CipherSuiteBox.Items)
        {
            if (item is System.Windows.Controls.ComboBoxItem comboBoxItem && Equals(comboBoxItem.Tag, tag))
            {
                CipherSuiteBox.SelectedItem = comboBoxItem;
                return;
            }
        }

        CipherSuiteBox.SelectedIndex = 0;
    }
}

internal enum DropTarget
{
    Auto,
    Inputs,
    TargetArchive,
    ExtractArchive,
    OutputFolder,
    EraseTarget,
}

internal enum DropResult
{
    None,
    InputsAdded,
    TargetArchiveSet,
    ExtractArchiveSet,
    OutputFolderSet,
    EraseTargetSet,
}
