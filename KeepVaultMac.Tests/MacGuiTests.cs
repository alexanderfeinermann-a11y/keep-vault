using System.Collections.Concurrent;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using KalynaArchiver;
using KalynaArchiver.Services;

/// <summary>
/// Drives the real <see cref="MainWindow"/> through Avalonia's headless
/// windowing backend.
/// </summary>
/// <remarks>
/// The window, its XAML, its event wiring and its code-behind are exactly the
/// ones the signed app ships; only the platform backend is swapped for one that
/// needs no display. Input is injected as genuine pointer and property events
/// rather than by calling handlers directly, so the wiring itself is under test.
/// </remarks>
internal static class MacGuiTests
{
    /// <summary>Settings store that keeps preferences in memory.</summary>
    /// <remarks>
    /// Keeps the suite from reading or writing the real user's isolated storage,
    /// so a test run cannot change what the installed app shows on next launch.
    /// </remarks>
    private sealed class InMemorySettingsStore : IAppSettingsStore
    {
        private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

        public string? Read(string key) => _values.TryGetValue(key, out string? value) ? value : null;

        public void Write(string key, string value) => _values[key] = value;
    }

    internal static TestCase[] Tests =>
    [
        new("GUI entropy display beyond the 512 minimum", () => RunOnUiThread(TestEntropyDisplayGrowsPastMinimum), TestResource.Gui, "GUI"),
        new("GUI encryption toggle and target normalization", () => RunOnUiThread(TestEncryptionToggle), TestResource.Gui, "GUI"),
        new("GUI folder target lands beside the folder", () => RunOnUiThread(TestFolderTargetSuggestion), TestResource.Gui, "GUI"),
        new("GUI password policy feedback", () => RunOnUiThread(TestPasswordPolicyFeedback), TestResource.Gui, "GUI"),
        new("GUI verified-original-deletion localization", () => RunOnUiThread(TestDeleteOriginalsLocalization), TestResource.Gui, "GUI"),
        new("GUI reference control inventory", () => RunOnUiThread(TestReferenceControlsPresent), TestResource.Gui, "GUI"),
        new("GUI 256-character factor normalization and field handling", () => RunOnUiThread(TestFactorBoxesLengthAndNormalization), TestResource.Gui, "GUI"),
        new("GUI secret clearing wipes password, PIN, and factors", () => RunOnUiThread(TestSecretClearing), TestResource.Gui, "GUI"),
        new("GUI KDF and entropy profile description localization", () => RunOnUiThread(TestKdfAndEntropyLocalization), TestResource.Gui, "GUI"),
        new("GUI full creation flow with mouse sampling and factor generation", () => RunOnUiThread(TestFullCreationFlowViaGui), TestResource.Gui, "GUI"),
    ];

    private static readonly BlockingCollection<(Action<MainWindow> Body, TaskCompletionSource Completion)> Work = new();
    private static Thread? _uiThread;

    /// <summary>
    /// Starts the single thread that owns the Avalonia headless platform, if it
    /// is not running yet.
    /// </summary>
    /// <remarks>
    /// Avalonia binds its UI thread to whichever thread sets the platform up,
    /// and the platform can only be set up once per process. A thread per test
    /// would therefore leave every test after the first queueing work onto a
    /// dispatcher whose thread has already exited, where it waits forever. One
    /// long-lived worker serves them all instead; the surrounding suite keeps
    /// the process main thread.
    /// </remarks>
    private static void EnsureUiThread()
    {
        if (_uiThread is not null)
        {
            return;
        }

        using var ready = new ManualResetEventSlim();
        Exception? startupFailure = null;
        _uiThread = new Thread(
            () =>
            {
                try
                {
                    AppBuilder.Configure<App>()
                        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true })
                        .SetupWithoutStarting();
                }
                catch (Exception ex)
                {
                    startupFailure = ex;
                    return;
                }
                finally
                {
                    ready.Set();
                }

                // This thread is the UI thread, so each body runs inline; the
                // bodies pump the dispatcher themselves where they need to.
                foreach ((Action<MainWindow> body, TaskCompletionSource completion) in Work.GetConsumingEnumerable())
                {
                    MainWindow? window = null;
                    try
                    {
                        window = new MainWindow(new InMemorySettingsStore());
                        window.Show();
                        Dispatcher.UIThread.RunJobs();
                        body(window);
                        completion.SetResult();
                    }
                    catch (Exception ex)
                    {
                        completion.SetException(ex);
                    }
                    finally
                    {
                        try
                        {
                            window?.Close();
                            window?.Dispose();
                            Dispatcher.UIThread.RunJobs();
                        }
                        catch (Exception)
                        {
                            // A teardown fault must not mask the test result.
                        }
                    }
                }
            },
            maxStackSize: 16 * 1024 * 1024)
        {
            IsBackground = true,
            Name = "KeepVault headless UI",
        };

        _uiThread.Start();
        ready.Wait();
        if (startupFailure is not null)
        {
            throw new InvalidOperationException(
                $"The Avalonia headless platform could not be initialised: {startupFailure.Message}",
                startupFailure);
        }
    }

    private static async Task RunOnUiThread(Action<MainWindow> body)
    {
        EnsureUiThread();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Work.Add((body, completion));
        Task finished = await Task.WhenAny(completion.Task, Task.Delay(TimeSpan.FromMinutes(3))).ConfigureAwait(false);
        if (finished != completion.Task)
        {
            throw new TimeoutException("The headless GUI test did not finish within three minutes.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    private static T Control<T>(MainWindow window, string name)
        where T : Control
        => window.FindControl<T>(name)
            ?? throw new InvalidOperationException($"The reference control is missing from the macOS window: {name}");

    private static void MoveMouse(MainWindow window, int moves)
    {
        for (int index = 0; index < moves; index++)
        {
            // Vary both axes so successive samples differ in more than one field.
            window.MouseMove(new Point(11 + (index % 337), 13 + (index % 521)));
        }

        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// 512 samples per pool is the threshold that unlocks generation, not a
    /// ceiling. Collection continues while the pointer moves, and the reported
    /// counts have to keep rising with it — an earlier build clamped the value
    /// the throttle compared against, which froze the entire status line at the
    /// threshold and made 512 look like a maximum.
    /// </summary>
    private static void TestEntropyDisplayGrowsPastMinimum(MainWindow window)
    {
        TextBlock status = Control<TextBlock>(window, "EntropyStatusText");
        ProgressBar progress = Control<ProgressBar>(window, "EntropyProgress");
        long required = EntropyMixer.RequiredMouseSamplesPerPurpose;

        long guard = 0;
        while (EntropyMixer.GetPoolStatus().Minimum < required)
        {
            MoveMouse(window, 512);
            if (++guard > 200)
            {
                throw new InvalidOperationException("The entropy pools never reached the required minimum.");
            }
        }

        EntropyPoolStatus atThreshold = EntropyMixer.GetPoolStatus();
        string textAtThreshold = status.Text ?? string.Empty;
        double progressAtThreshold = progress.Value;
        MacComprehensiveTests.Require(
            atThreshold.Minimum >= required,
            "The entropy pools did not reach the required minimum.");
        MacComprehensiveTests.Require(
            Control<Button>(window, "GeneratePasswordButton").IsEnabled,
            "Generation stayed locked after every pool reached the required minimum.");

        MoveMouse(window, 2560);

        EntropyPoolStatus beyond = EntropyMixer.GetPoolStatus();
        MacComprehensiveTests.Require(
            beyond.Minimum > atThreshold.Minimum,
            $"Sampling stopped at the {required}-sample minimum instead of continuing: {beyond.Minimum}.");
        MacComprehensiveTests.Require(
            beyond.Total > atThreshold.Total,
            "The total sample count stopped growing past the minimum.");
        MacComprehensiveTests.Require(
            !string.Equals(status.Text ?? string.Empty, textAtThreshold, StringComparison.Ordinal),
            "The entropy status line froze at the minimum instead of reporting the additional samples.");
        // The readout is refreshed when the pool minimum moves, which happens
        // once per full round across the pools rather than on every sample. It
        // may therefore trail the running total by up to one round; what it must
        // not do is stop catching up. Sampling until it agrees checks exactly
        // that, without assuming a particular number of pools.
        long reportedTotal = 0;
        for (int round = 0; round < 16; round++)
        {
            reportedTotal = EntropyMixer.GetPoolStatus().Total;
            if ((status.Text ?? string.Empty).Contains(
                    reportedTotal.ToString(CultureInfo.CurrentCulture),
                    StringComparison.Ordinal))
            {
                break;
            }

            MoveMouse(window, 1);
        }

        MacComprehensiveTests.Require(
            (status.Text ?? string.Empty).Contains(reportedTotal.ToString(CultureInfo.CurrentCulture), StringComparison.Ordinal),
            "The entropy status line never caught up with the current total sample count.");

        // The bar measures progress towards the minimum, so it stays full while
        // the reported counts keep climbing.
        MacComprehensiveTests.Require(
            Math.Abs(progress.Value - required) < 0.5 && Math.Abs(progressAtThreshold - required) < 0.5,
            "The entropy progress bar does not represent progress towards the required minimum.");
    }

    /// <summary>
    /// The encryption checkbox is wired in code rather than XAML on this
    /// platform, so drive the real control and assert the effects the Windows
    /// reference produces: the cipher selection follows the checkbox and the
    /// target archive extension is rewritten.
    /// </summary>
    /// <summary>
    /// A folder input must not suggest an archive inside that same folder.
    /// </summary>
    /// <remarks>
    /// Suggesting a target inside the input produced a path the safety check
    /// then refused, which reads to the user as the app objecting to a folder
    /// and a same-named archive coexisting. The suggestion has to be a path the
    /// app will actually accept.
    /// </remarks>
    private static void TestFolderTargetSuggestion(MainWindow window)
    {
        _ = window;
        string root = Directory.CreateTempSubdirectory("keep-vault-target-").FullName;
        try
        {
            string folder = Path.Combine(root, "Docs");
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "note.txt"), "content");
            File.WriteAllText(Path.Combine(root, "Docs.zip"), "not really a zip");

            string suggestion = MainWindow.SuggestTargetArchivePath(folder, encrypted: true);

            MacComprehensiveTests.Require(
                !suggestion.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.Ordinal),
                $"The suggested archive target is inside its own input folder: {suggestion}");
            MacComprehensiveTests.Require(
                string.Equals(Path.GetDirectoryName(suggestion), root, StringComparison.Ordinal),
                $"The suggested archive target is not beside the input folder: {suggestion}");
            MacComprehensiveTests.Require(
                Path.GetFileName(suggestion).StartsWith("Docs(", StringComparison.Ordinal),
                $"The suggested archive target is not named after the folder: {suggestion}");
            MacComprehensiveTests.Require(
                !File.Exists(suggestion) && !Directory.Exists(suggestion),
                $"The suggested archive target already exists: {suggestion}");

            // A same-named zip beside the folder must not block the folder: the
            // numbered name is claimed against what is actually on disk, so
            // once one target exists the next suggestion moves on by itself.
            string fromZip = MainWindow.SuggestTargetArchivePath(Path.Combine(root, "Docs.zip"), encrypted: true);
            MacComprehensiveTests.Require(
                !File.Exists(fromZip) && !Directory.Exists(fromZip),
                $"The suggested target for the same-named archive already exists: {fromZip}");

            File.WriteAllText(suggestion, "placeholder");
            string afterTaken = MainWindow.SuggestTargetArchivePath(folder, encrypted: true);
            MacComprehensiveTests.Require(
                !string.Equals(afterTaken, suggestion, StringComparison.Ordinal)
                    && !File.Exists(afterTaken),
                $"An occupied target name was suggested again: {afterTaken}");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestEncryptionToggle(MainWindow window)
    {
        CheckBox encrypt = Control<CheckBox>(window, "EncryptBox");
        ComboBox cipher = Control<ComboBox>(window, "CipherSuiteBox");
        TextBox archive = Control<TextBox>(window, "ArchivePathBox");
        Border passwordPanel = Control<Border>(window, "CreatePasswordPanel");

        MacComprehensiveTests.Require(encrypt.IsChecked == true, "Encryption is not the default.");

        archive.Text = "/tmp/keep-vault-gui/archive.kzpaq";
        encrypt.IsChecked = false;
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(!cipher.IsEnabled, "The cipher suite stayed selectable without encryption.");
        MacComprehensiveTests.Require(!passwordPanel.IsEnabled, "The password panel stayed active without encryption.");
        MacComprehensiveTests.Require(
            string.Equals(archive.Text, "/tmp/keep-vault-gui/archive.zpaq", StringComparison.Ordinal),
            $"The target archive extension was not normalized for a plain archive: {archive.Text}");

        encrypt.IsChecked = true;
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(cipher.IsEnabled, "The cipher suite stayed locked after re-enabling encryption.");
        MacComprehensiveTests.Require(passwordPanel.IsEnabled, "The password panel stayed disabled after re-enabling encryption.");
        MacComprehensiveTests.Require(
            string.Equals(archive.Text, "/tmp/keep-vault-gui/archive.kzpaq", StringComparison.Ordinal),
            $"The target archive extension was not restored for an encrypted archive: {archive.Text}");
    }

    /// <summary>
    /// Typing into the user-password box has to drive the live policy readout,
    /// which is the only feedback a user gets before the archive is created.
    /// </summary>
    private static void TestPasswordPolicyFeedback(MainWindow window)
    {
        TextBox password = Control<TextBox>(window, "CreatePasswordBox");
        TextBlock entropy = Control<TextBlock>(window, "PasswordEntropyStatusText");

        password.Text = "kurz";
        Dispatcher.UIThread.RunJobs();
        string weakText = entropy.Text ?? string.Empty;
        MacComprehensiveTests.Require(weakText.Length > 0, "The password policy readout stayed empty for a weak password.");

        PasswordPolicyAnalysis weak = PasswordKeyService.AnalyzeUserPassword("kurz", string.Empty, string.Empty);
        MacComprehensiveTests.Require(!weak.IsAccepted, "A four-character password was treated as acceptable.");

        const string strong = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        password.Text = strong;
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(
            !string.Equals(entropy.Text ?? string.Empty, weakText, StringComparison.Ordinal),
            "The password policy readout did not react to a changed password.");

        PasswordPolicyAnalysis accepted = PasswordKeyService.AnalyzeUserPassword(strong, string.Empty, string.Empty);
        MacComprehensiveTests.Require(accepted.IsAccepted, "The reference-strength password was rejected by the policy.");

        TestPinPolicyFeedback(window);
    }

    /// <summary>
    /// The PIN readout has to behave like the password readout: it is a
    /// credential of equal standing in v10, and an archive cannot be opened
    /// without it.
    /// </summary>
    private static void TestPinPolicyFeedback(MainWindow window)
    {
        TextBox pin = Control<TextBox>(window, "CreatePinBox");
        TextBox confirm = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBlock readout = Control<TextBlock>(window, "PinPolicyStatusText");

        pin.Text = "123";
        confirm.Text = "123";
        Dispatcher.UIThread.RunJobs();
        string tooShort = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            tooShort.Length > 0,
            "The PIN readout stayed empty for a PIN that is too short.");

        pin.Text = "428317";
        confirm.Text = "428318";
        Dispatcher.UIThread.RunJobs();
        string mismatched = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            !string.Equals(mismatched, tooShort, StringComparison.Ordinal),
            "The PIN readout did not react to two differing PIN entries.");

        pin.Text = "428317";
        confirm.Text = "428317";
        Dispatcher.UIThread.RunJobs();
        string acceptedText = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            !string.Equals(acceptedText, mismatched, StringComparison.Ordinal)
                && !string.Equals(acceptedText, tooShort, StringComparison.Ordinal),
            "The PIN readout did not accept a valid, matching PIN.");

        // A letter is not a digit, and the derivation refuses it -- the readout
        // has to say so here rather than at the end of an archive run.
        pin.Text = "42831A";
        confirm.Text = "42831A";
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(
            !string.Equals(readout.Text ?? string.Empty, acceptedText, StringComparison.Ordinal),
            "The PIN readout accepted a non-digit PIN.");

        pin.Text = string.Empty;
        confirm.Text = string.Empty;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// The destructive option and its safety explanation must follow the
    /// language picker together. The XAML starts in German, so testing an actual
    /// switch to English catches controls that were never wired into
    /// ApplyLanguage rather than merely checking their initial text.
    /// </summary>
    private static void TestDeleteOriginalsLocalization(MainWindow window)
    {
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        CheckBox deleteOriginals = Control<CheckBox>(window, "DeleteOriginalsBox");
        TextBlock deleteOriginalsHint = Control<TextBlock>(window, "DeleteOriginalsHint");

        SelectLanguage(language, "de");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginals.Content as string,
                "Originaldateien nach geprüftem Abgleich löschen",
                StringComparison.Ordinal),
            "The verified-original-deletion option is not localized in German.");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginalsHint.Text,
                "Das Archiv wird danach erneut entpackt und bitweise mit den Originalen verglichen. Gelöscht wird erst bei vollständiger Übereinstimmung.",
                StringComparison.Ordinal),
            "The verified-original-deletion explanation is not localized in German.");

        SelectLanguage(language, "en");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginals.Content as string,
                "Delete original files after a verified comparison",
                StringComparison.Ordinal),
            "The verified-original-deletion option is not localized in English.");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginalsHint.Text,
                "The archive is then extracted again and compared byte-for-byte with the original files. Files are deleted only after a complete match.",
                StringComparison.Ordinal),
            "The verified-original-deletion explanation is not localized in English.");
    }

    private static void SelectLanguage(ComboBox language, string expectedTag)
    {
        ComboBoxItem item = language.Items
            .OfType<ComboBoxItem>()
            .Single(candidate => string.Equals(candidate.Tag as string, expectedTag, StringComparison.Ordinal));
        language.SelectedItem = item;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// Every interactive control the Windows reference exposes must exist here
    /// too, so a renamed or dropped control fails the suite instead of silently
    /// removing a capability from the macOS build.
    /// </summary>
    private static void TestReferenceControlsPresent(MainWindow window)
    {
        string[] referenceControls =
        [
            "EncryptBox", "CipherSuiteBox", "CompressionBox", "ArchivePathBox", "InputList",
            "CreatePasswordBox", "CreatePasswordConfirmBox",
            "CreatePinBox", "CreatePinConfirmBox", "PinPolicyStatusText",
            "GeneratedPasswordFirstBox",
            "GeneratedPasswordSecondBox", "GeneratePasswordButton", "EntropyStatusText",
            "DeleteOriginalsBox", "DeleteOriginalsHint",
            "ExtractArchiveBox", "OutputFolderBox", "ExtractPasswordBox",
            "ExtractPinBox",
            "ExtractGeneratedPasswordFirstBox", "ExtractGeneratedPasswordSecondBox",
            "ErasePathBox", "LogBox", "ClearLogButton", "LanguageBox",
        ];

        foreach (string name in referenceControls)
        {
            MacComprehensiveTests.Require(
                window.FindControl<Control>(name) is not null,
                $"The macOS window is missing the reference control: {name}");
        }
    }

    /// <summary>
    /// Extraction factor boxes must accept formatted 256-hex character factors
    /// (with spaces or linebreaks as printed on key sheets) and normalize them.
    /// </summary>
    private static void TestFactorBoxesLengthAndNormalization(MainWindow window)
    {
        TextBox extractFactorA = Control<TextBox>(window, "ExtractGeneratedPasswordFirstBox");
        TextBox extractFactorB = Control<TextBox>(window, "ExtractGeneratedPasswordSecondBox");

        // 256-hex characters factor (128 bytes)
        string rawHexA = new string('A', 256);
        string formattedHexA = string.Join(" ", Enumerable.Range(0, 4).Select(i => rawHexA.Substring(i * 64, 64)));
        string rawHexB = new string('B', 256);

        extractFactorA.Text = formattedHexA;
        extractFactorB.Text = rawHexB;
        Dispatcher.UIThread.RunJobs();

        string normalizedA = MainWindow.EnsureGeneratedPassword(extractFactorA.Text);
        string normalizedB = MainWindow.EnsureGeneratedPassword(extractFactorB.Text);

        MacComprehensiveTests.Require(
            string.Equals(normalizedA, rawHexA, StringComparison.Ordinal),
            "Whitespace-formatted 256-hex factor was not correctly normalized.");
        MacComprehensiveTests.Require(
            string.Equals(normalizedB, rawHexB, StringComparison.Ordinal),
            "Factor B was not correctly normalized.");
        MacComprehensiveTests.Require(
            normalizedA.Length == 256 && normalizedB.Length == 256,
            "Normalized factor length is not 256 characters.");

        // Rejection of invalid factors
        bool threwShort = false;
        try { MainWindow.EnsureGeneratedPassword(new string('C', 255)); } catch (Exception) { threwShort = true; }
        MacComprehensiveTests.Require(threwShort, "EnsureGeneratedPassword did not reject 255-character factor.");

        bool threwInvalidChar = false;
        try { MainWindow.EnsureGeneratedPassword(new string('A', 255) + "Z"); } catch (Exception) { threwInvalidChar = true; }
        MacComprehensiveTests.Require(threwInvalidChar, "EnsureGeneratedPassword did not reject non-hex character.");

        extractFactorA.Text = string.Empty;
        extractFactorB.Text = string.Empty;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// Secret clearing must wipe user password, PIN, confirm PIN, and generated factors.
    /// </summary>
    private static void TestSecretClearing(MainWindow window)
    {
        TextBox createPassword = Control<TextBox>(window, "CreatePasswordBox");
        TextBox createConfirm = Control<TextBox>(window, "CreatePasswordConfirmBox");
        TextBox createPin = Control<TextBox>(window, "CreatePinBox");
        TextBox createPinConfirm = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBox factorA = Control<TextBox>(window, "GeneratedPasswordFirstBox");
        TextBox factorB = Control<TextBox>(window, "GeneratedPasswordSecondBox");

        createPassword.Text = "SecretPassword123!456";
        createConfirm.Text = "SecretPassword123!456";
        createPin.Text = "428317";
        createPinConfirm.Text = "428317";
        factorA.Text = new string('A', 256);
        factorB.Text = new string('B', 256);
        Dispatcher.UIThread.RunJobs();

        window.ClearCreateSecrets();
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPassword.Text), "CreatePasswordBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createConfirm.Text), "CreatePasswordConfirmBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPin.Text), "CreatePinBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPinConfirm.Text), "CreatePinConfirmBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorA.Text), "GeneratedPasswordFirstBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorB.Text), "GeneratedPasswordSecondBox was not cleared.");

        TextBox extractPassword = Control<TextBox>(window, "ExtractPasswordBox");
        TextBox extractPin = Control<TextBox>(window, "ExtractPinBox");
        TextBox extractFactorA = Control<TextBox>(window, "ExtractGeneratedPasswordFirstBox");
        TextBox extractFactorB = Control<TextBox>(window, "ExtractGeneratedPasswordSecondBox");

        extractPassword.Text = "SecretPassword123!456";
        extractPin.Text = "428317";
        extractFactorA.Text = new string('A', 256);
        extractFactorB.Text = new string('B', 256);
        Dispatcher.UIThread.RunJobs();

        window.ClearExtractSecrets();
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPassword.Text), "ExtractPasswordBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPin.Text), "ExtractPinBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorA.Text), "ExtractGeneratedPasswordFirstBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorB.Text), "ExtractGeneratedPasswordSecondBox was not cleared.");
    }

    /// <summary>
    /// KDF description and entropy pool readout must correctly localize in German and English.
    /// </summary>
    private static void TestKdfAndEntropyLocalization(MainWindow window)
    {
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        TextBlock kdfProfile = Control<TextBlock>(window, "Argon2ProfileText");

        SelectLanguage(language, "de");
        string deKdf = kdfProfile.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            deKdf.Contains("1024-Bit-Master", StringComparison.Ordinal) || deKdf.Contains("KDF-Pfade", StringComparison.Ordinal),
            $"German KDF description is missing v10 master details: {deKdf}");

        SelectLanguage(language, "en");
        string enKdf = kdfProfile.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            enKdf.Contains("1024-bit master", StringComparison.Ordinal) || enKdf.Contains("KDF paths", StringComparison.Ordinal),
            $"English KDF description is missing v10 master details: {enKdf}");
    }

    /// <summary>
    /// Exercises the entire GUI creation flow: gathering 1024 mouse samples across the 9 pools
    /// via genuine pointer movement, clicking the factor generator button, filling out PIN and password,
    /// and validating the creation gate.
    /// </summary>
    private static void TestFullCreationFlowViaGui(MainWindow window)
    {
        // 1. Move mouse to feed all 9 entropy pools until minimum 1024 is reached
        long required = EntropyMixer.RequiredMouseSamplesPerPurpose;
        long guard = 0;
        while (EntropyMixer.GetPoolStatus().Minimum < required)
        {
            MoveMouse(window, 512);
            if (++guard > 200)
            {
                throw new InvalidOperationException("Entropy pools failed to reach required 1024 samples.");
            }
        }

        Button generateBtn = Control<Button>(window, "GeneratePasswordButton");
        MacComprehensiveTests.Require(generateBtn.IsEnabled, "GeneratePasswordButton stayed disabled after reaching 1024 samples.");

        // 2. Click generate button
        window.GeneratePassword_Click(generateBtn, new Avalonia.Interactivity.RoutedEventArgs());
        Dispatcher.UIThread.RunJobs();

        TextBox factorA = Control<TextBox>(window, "GeneratedPasswordFirstBox");
        TextBox factorB = Control<TextBox>(window, "GeneratedPasswordSecondBox");
        MacComprehensiveTests.Require(!string.IsNullOrEmpty(factorA.Text) && factorA.Text.Length == 256, "Factor A was not generated as 256 hex chars.");
        MacComprehensiveTests.Require(!string.IsNullOrEmpty(factorB.Text) && factorB.Text.Length == 256, "Factor B was not generated as 256 hex chars.");
        MacComprehensiveTests.Require(!string.Equals(factorA.Text, factorB.Text, StringComparison.Ordinal), "Factor A and Factor B must be distinct.");

        // 3. Set password and PIN
        TextBox password = Control<TextBox>(window, "CreatePasswordBox");
        TextBox confirm = Control<TextBox>(window, "CreatePasswordConfirmBox");
        TextBox pin = Control<TextBox>(window, "CreatePinBox");
        TextBox pinConfirm = Control<TextBox>(window, "CreatePinConfirmBox");

        const string validPass = "Valid#Master%Passphrase2026&v10!";
        password.Text = validPass;
        confirm.Text = validPass;
        pin.Text = "84920153";
        pinConfirm.Text = "84920153";
        Dispatcher.UIThread.RunJobs();

        TextBlock pinReadout = Control<TextBlock>(window, "PinPolicyStatusText");
        MacComprehensiveTests.Require(
            pinReadout.Text?.Contains("akzeptiert", StringComparison.OrdinalIgnoreCase) == true
            || pinReadout.Text?.Contains("accepted", StringComparison.OrdinalIgnoreCase) == true,
            $"Valid PIN was not reported as accepted by GUI readout: {pinReadout.Text}");

        // 4. Clear secrets
        window.ClearCreateSecrets();
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(string.IsNullOrEmpty(password.Text), "Password was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(pin.Text), "PIN was not cleared.");
    }
}
