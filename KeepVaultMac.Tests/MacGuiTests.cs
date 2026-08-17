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

    internal static (string Name, Func<Task> Run)[] Tests =>
    [
        ("GUI entropy display beyond the 512 minimum", () => RunOnUiThread(TestEntropyDisplayGrowsPastMinimum)),
        ("GUI encryption toggle and target normalization", () => RunOnUiThread(TestEncryptionToggle)),
        ("GUI folder target lands beside the folder", () => RunOnUiThread(TestFolderTargetSuggestion)),
        ("GUI password policy feedback", () => RunOnUiThread(TestPasswordPolicyFeedback)),
        ("GUI reference control inventory", () => RunOnUiThread(TestReferenceControlsPresent)),
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
            "CreatePasswordBox", "CreatePasswordConfirmBox", "GeneratedPasswordFirstBox",
            "GeneratedPasswordSecondBox", "GeneratePasswordButton", "EntropyStatusText",
            "ExtractArchiveBox", "OutputFolderBox", "ExtractPasswordBox",
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
}
