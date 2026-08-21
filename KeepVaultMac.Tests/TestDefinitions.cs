using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

internal enum TestResource
{
    Light,          // Thread-safe, low RAM/CPU: pure KATs, policies, non-conflicting descriptors
    CpuHeavy,       // Thread-safe CPU-intensive: ML-DSA, differential testing, per-chunk nonces
    ProcessGlobal,  // Serial preflight: modifies process-wide state (process hardening)
    ArgonHeavy,     // Serial: 1-2 GiB matrices, Argon2id equivalence
    ArgonPeakMemory,// Strictly exclusive: peak memory / RSS measurement
    EntropyGlobal,  // Serial: consumes shared EntropyMixer state
    ZpaqGlobal,     // Serial: ZPAQ extraction & limit testing
    Gui             // Serial: Avalonia headless UI-thread worker
}

internal sealed record TestCase(
    string Name,
    Func<Task> Run,
    TestResource Resource,
    string Category = "General",
    bool IsSmoke = false);

internal static class TestRunner
{
    private static readonly object ConsoleLock = new();

    internal static async Task<int> RunAsync(
        string[] args,
        IReadOnlyList<TestCase> smokeTests,
        IReadOnlyList<TestCase> comprehensiveTests)
    {
        bool listOnly = false;
        bool fullRequested = false;
        bool quickRequested = false;
        bool changedRequested = false;
        bool noSmokeRequested = false;
        bool smokeRequested = false;
        string? onlyFilter = null;
        string? smokeOnlyFilter = null;
        string? categoryFilter = null;
        int repeatCount = 1;
        int? parallelOverride = null;
        uint? seedOverride = null;
        string? baseRef = null;
        string? dumpKeySheetsDir = null;
        string timingsPath = Path.Combine(AppContext.BaseDirectory, ".test-timings.json");

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg.ToLowerInvariant())
            {
                case "--list":
                    listOnly = true;
                    break;
                case "--full":
                    fullRequested = true;
                    break;
                case "--quick":
                    quickRequested = true;
                    break;
                case "--changed":
                    changedRequested = true;
                    break;
                case "--no-smoke":
                    noSmokeRequested = true;
                    break;
                case "--smoke":
                    smokeRequested = true;
                    break;
                case "--only":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --only.");
                        return 64;
                    }
                    onlyFilter = args[++i];
                    break;
                case "--smoke-only":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --smoke-only.");
                        return 64;
                    }
                    smokeOnlyFilter = args[++i];
                    break;
                case "--category":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --category.");
                        return 64;
                    }
                    categoryFilter = args[++i];
                    break;
                case "--repeat":
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int r) || r < 1)
                    {
                        Console.Error.WriteLine("Usage error: --repeat requires an integer >= 1.");
                        return 64;
                    }
                    repeatCount = r;
                    i++;
                    break;
                case "--parallel":
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int p) || (p != -1 && (p < 1 || p > 128)))
                    {
                        Console.Error.WriteLine("Usage error: --parallel requires -1 or an integer between 1 and 128.");
                        return 64;
                    }
                    parallelOverride = p;
                    i++;
                    break;
                case "--seed":
                    if (i + 1 >= args.Length)
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --seed.");
                        return 64;
                    }
                    string seedStr = args[++i];
                    uint? parsedSeed = seedStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? (uint.TryParse(seedStr[2..], System.Globalization.NumberStyles.HexNumber, null, out uint sHex) ? sHex : null)
                        : (uint.TryParse(seedStr, out uint sDec) ? sDec : null);
                    if (parsedSeed == null)
                    {
                        Console.Error.WriteLine($"Usage error: Invalid seed value '{seedStr}'. Expected 32-bit unsigned integer or hex (e.g. 0x12345678).");
                        return 64;
                    }
                    seedOverride = parsedSeed;
                    break;
                case "--base":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --base.");
                        return 64;
                    }
                    baseRef = args[++i];
                    break;
                case "--dump-key-sheets":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --dump-key-sheets.");
                        return 64;
                    }
                    dumpKeySheetsDir = args[++i];
                    break;
                case "--timings":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --timings.");
                        return 64;
                    }
                    timingsPath = args[++i];
                    break;
                default:
                    Console.Error.WriteLine($"Usage error: Unrecognized argument '{arg}'.");
                    return 64;
            }
        }

        if (listOnly)
        {
            Console.WriteLine("Available Smoke Tests:");
            foreach (var test in smokeTests)
            {
                Console.WriteLine($"  [Smoke] [{test.Resource,-13}] {test.Name}");
            }
            Console.WriteLine();
            Console.WriteLine("Available Comprehensive Tests:");
            foreach (var test in comprehensiveTests)
            {
                Console.WriteLine($"  [{test.Category,-11}] [{test.Resource,-15}] {test.Name}");
            }
            return 0;
        }

        // Determine which tests to include
        var selectedSmoke = new List<TestCase>();
        var selectedComprehensive = new List<TestCase>();

        if (changedRequested)
        {
            HashSet<string>? affectedNames = DetermineAffectedTestsFromGit(baseRef);
            if (affectedNames == null)
            {
                Console.WriteLine("Note: Git impact detection could not determine changed files; running full test suite.");
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests);
            }
            else if (affectedNames.Count == 0)
            {
                // Fallback: run smoke + light tests
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
            }
            else
            {
                selectedSmoke.AddRange(smokeTests.Where(t => affectedNames.Contains(t.Name) || affectedNames.Contains("ALL_SMOKE")));
                selectedComprehensive.AddRange(comprehensiveTests.Where(t => affectedNames.Contains(t.Name) || affectedNames.Contains("ALL_COMPREHENSIVE")));
                if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
                {
                    selectedSmoke.AddRange(smokeTests);
                    selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
                }
            }
        }
        else if (quickRequested)
        {
            selectedSmoke.AddRange(smokeTests);
            selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
        }
        else
        {
            // Smoke test selection
            if (!noSmokeRequested && (onlyFilter is null || smokeOnlyFilter is not null || smokeRequested))
            {
                if (smokeOnlyFilter is not null)
                {
                    selectedSmoke.AddRange(smokeTests.Where(t => t.Name.Contains(smokeOnlyFilter, StringComparison.OrdinalIgnoreCase)));
                }
                else
                {
                    selectedSmoke.AddRange(smokeTests);
                }
            }

            // Comprehensive test selection
            if (fullRequested || onlyFilter is not null || categoryFilter is not null)
            {
                IEnumerable<TestCase> comp = comprehensiveTests;
                if (onlyFilter is not null)
                {
                    comp = comp.Where(t => t.Name.Contains(onlyFilter, StringComparison.OrdinalIgnoreCase));
                }
                if (categoryFilter is not null)
                {
                    comp = comp.Where(t =>
                        string.Equals(t.Category, categoryFilter, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(t.Resource.ToString(), categoryFilter, StringComparison.OrdinalIgnoreCase));
                }
                selectedComprehensive.AddRange(comp);
            }
        }

        if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
        {
            Console.WriteLine("No tests matched the specified criteria.");
            bool explicitSelector = onlyFilter != null || smokeOnlyFilter != null || categoryFilter != null;
            return explicitSelector ? 64 : 0;
        }

        // Determine worker count
        int workerCount = parallelOverride
            ?? (int.TryParse(Environment.GetEnvironmentVariable("KEEPVAULT_TEST_WORKERS"), out int envWorkers)
                ? Math.Clamp(envWorkers, 1, 32)
                : Math.Clamp(Environment.ProcessorCount / 2, 2, 8));

        // Load cached timings for Longest-Processing-Time (LPT) scheduling
        Dictionary<string, double> cachedTimings = LoadTimings(timingsPath);
        var currentRunTimings = new ConcurrentDictionary<string, double>(cachedTimings);

        // Run iterations (if --repeat N)
        for (int iteration = 1; iteration <= repeatCount; iteration++)
        {
            if (repeatCount > 1)
            {
                Console.WriteLine($"=== Test Iteration {iteration} of {repeatCount} ===");
            }

            Stopwatch totalTimer = Stopwatch.StartNew();

            // 1. Run Smoke Tests (Parallel Light execution)
            if (selectedSmoke.Count > 0)
            {
                bool smokeSuccess = await RunSmokeBatchAsync(selectedSmoke, workerCount, cachedTimings, currentRunTimings);
                if (!smokeSuccess)
                {
                    return 1;
                }
                Console.WriteLine($"{selectedSmoke.Count} macOS smoke tests passed.");
            }

            // 2. Run Comprehensive Tests in 4 Orchestrated Phases
            if (selectedComprehensive.Count > 0)
            {
                bool compSuccess = await RunComprehensiveSuiteAsync(
                    selectedComprehensive,
                    workerCount,
                    cachedTimings,
                    currentRunTimings,
                    seedOverride);

                if (!compSuccess)
                {
                    return 1;
                }

                Console.WriteLine($"{selectedComprehensive.Count} comprehensive macOS functional/cryptographic groups passed.");
            }

            totalTimer.Stop();
        }

        // Save timings
        SaveTimings(timingsPath, currentRunTimings);

        // Process --dump-key-sheets if passed
        if (!string.IsNullOrEmpty(dumpKeySheetsDir))
        {
            DumpKeySheets(dumpKeySheetsDir);
        }

        return 0;
    }

    private static async Task<bool> RunSmokeBatchAsync(
        IReadOnlyList<TestCase> tests,
        int workerCount,
        Dictionary<string, double> cachedTimings,
        ConcurrentDictionary<string, double> currentTimings)
    {
        var sorted = tests
            .OrderByDescending(t => cachedTimings.GetValueOrDefault(t.Name, 0.0))
            .ToList();

        bool allPassed = true;

        foreach (TestCase test in sorted)
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                await test.Run().ConfigureAwait(false);
                sw.Stop();
                currentTimings[test.Name] = sw.Elapsed.TotalSeconds;

                lock (ConsoleLock)
                {
                    Console.WriteLine($"PASS {test.Name}");
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                allPassed = false;
                lock (ConsoleLock)
                {
                    Console.WriteLine();
                    Console.WriteLine($"FAIL Smoke: {test.Name}");
                    Console.WriteLine($"  {ex.GetType().Name}: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"  Inner: {ex.InnerException.Message}");
                    }
                    Console.WriteLine();
                    Console.WriteLine("Re-run:");
                    Console.WriteLine($"  dotnet run --no-build --no-restore --project KeepVaultMac.Tests -c Release -- --smoke-only \"{test.Name}\"");
                    Console.WriteLine();
                }
            }
        }

        return allPassed;
    }

    private static async Task<bool> RunComprehensiveSuiteAsync(
        IReadOnlyList<TestCase> tests,
        int workerCount,
        Dictionary<string, double> cachedTimings,
        ConcurrentDictionary<string, double> currentTimings,
        uint? seedOverride)
    {
        // Partition tests into 4 phases
        var processGlobalTests = tests.Where(t => t.Resource == TestResource.ProcessGlobal).ToList();
        var parallelTests = tests.Where(t => t.Resource is TestResource.Light or TestResource.CpuHeavy).ToList();
        var serialResourceTests = tests.Where(t => t.Resource is TestResource.ArgonHeavy or TestResource.ArgonPeakMemory or TestResource.EntropyGlobal or TestResource.ZpaqGlobal).ToList();
        var guiTests = tests.Where(t => t.Resource == TestResource.Gui).ToList();

        // Phase 1: Process-Global Preflight (Serial)
        foreach (var test in processGlobalTests)
        {
            if (!await RunSingleTestAsync(test, currentTimings, seedOverride)) return false;
        }

        // Phase 2: Parallel Light & CpuHeavy Tests (LPT Scheduled)
        if (parallelTests.Count > 0)
        {
            var sortedParallel = parallelTests
                .OrderByDescending(t => cachedTimings.GetValueOrDefault(t.Name, 0.0))
                .ToList();

            bool parallelPassed = true;
            await Parallel.ForEachAsync(
                sortedParallel,
                new ParallelOptions { MaxDegreeOfParallelism = workerCount },
                async (test, ct) =>
                {
                    if (!await RunSingleTestAsync(test, currentTimings, seedOverride))
                    {
                        parallelPassed = false;
                    }
                });

            if (!parallelPassed) return false;
        }

        // Phase 3: Serial Heavy & Global State Tests
        // Order: ArgonHeavy -> ArgonPeakMemory -> ZpaqGlobal -> EntropyGlobal
        var orderedSerial = serialResourceTests
            .OrderBy(t => t.Resource switch
            {
                TestResource.ArgonHeavy => 1,
                TestResource.ArgonPeakMemory => 2,
                TestResource.ZpaqGlobal => 3,
                TestResource.EntropyGlobal => 4,
                _ => 5
            })
            .ToList();

        foreach (var test in orderedSerial)
        {
            if (!await RunSingleTestAsync(test, currentTimings, seedOverride)) return false;
        }

        // Phase 4: GUI Tests (Serial on Headless UI worker)
        foreach (var test in guiTests)
        {
            if (!await RunSingleTestAsync(test, currentTimings, seedOverride)) return false;
        }

        return true;
    }

    private static async Task<bool> RunSingleTestAsync(
        TestCase test,
        ConcurrentDictionary<string, double> currentTimings,
        uint? seedOverride)
    {
        uint seed = seedOverride ?? checked((uint)RandomNumberGenerator.GetInt32(1, int.MaxValue));
        MacComprehensiveTests.TestSeed = seed;
        MacComprehensiveTests.SetCurrentPrng(new Random((int)seed));

        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            await test.Run().ConfigureAwait(false);
            sw.Stop();
            double seconds = sw.Elapsed.TotalSeconds;
            currentTimings[test.Name] = seconds;

            lock (ConsoleLock)
            {
                Console.WriteLine($"FULL PASS {test.Name} ({seconds:F1}s)");
            }
            return true;
        }
        catch (Exception ex)
        {
            sw.Stop();
            lock (ConsoleLock)
            {
                Console.WriteLine();
                Console.WriteLine($"FAIL {test.Name}");
                Console.WriteLine($"  seed=0x{seed:X8}");
                Console.WriteLine($"  {ex.GetType().Name}: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"  Inner: {ex.InnerException.Message}");
                }
                Console.WriteLine(ex.StackTrace);
                Console.WriteLine();
                Console.WriteLine("Re-run:");
                Console.WriteLine($"  dotnet run --no-build --no-restore --project KeepVaultMac.Tests -c Release -- --full --no-smoke --only \"{test.Name}\" --seed 0x{seed:X8}");
                Console.WriteLine();
            }
            return false;
        }
    }

    private static HashSet<string>? DetermineAffectedTestsFromGit(string? baseRef)
    {
        var affected = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            List<string> diffArgsList = new();
            if (!string.IsNullOrWhiteSpace(baseRef))
            {
                diffArgsList.Add($"diff --name-only {baseRef}...HEAD");
            }
            else
            {
                diffArgsList.Add("diff --name-only HEAD");
                diffArgsList.Add("diff --name-only --cached");
                diffArgsList.Add("diff --name-only HEAD~1...HEAD");
            }

            var allFiles = new HashSet<string>(StringComparer.Ordinal);
            bool anySuccess = false;

            foreach (string gitArg in diffArgsList)
            {
                using var proc = new Process();
                proc.StartInfo.FileName = "git";
                proc.StartInfo.Arguments = gitArg;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.StartInfo.CreateNoWindow = true;
                if (proc.Start())
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    if (proc.ExitCode == 0)
                    {
                        anySuccess = true;
                        string[] files = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        foreach (var f in files) allFiles.Add(f);
                    }
                }
            }

            if (!anySuccess)
            {
                return null;
            }

            if (allFiles.Count == 0)
            {
                return affected;
            }

            foreach (string file in allFiles)
            {
                bool matched = false;
                if (file.Contains("V10MasterKdf") || file.Contains("V10Primitives") || file.Contains("PasswordKeyService") || file.Contains("V10KeyDerivation") || file.Contains("SecureMemory"))
                {
                    matched = true;
                    affected.Add("v10 primitives against independent second implementations");
                    affected.Add("v10 master KDF: credential binding, PMI range and round chaining");
                    affected.Add("Argon2id fixed 1 GiB profile and independent equivalence");
                    affected.Add("v10 peak memory stays at one Argon2 matrix, and the header leaks nothing");
                    affected.Add("password policy and KEEPVAULT term rejection");
                    affected.Add("v10 creation PIN policy and weak-pattern rejection");
                    affected.Add("v10 suite roundtrips and manipulation rejection");
                }
                if (file.Contains("ZpaqService") || file.Contains("MacPlatformSecurity") || file.Contains("MacSecureFile") || file.Contains("MacOriginalDeletionService"))
                {
                    matched = true;
                    affected.Add("ZPAQ levels, streaming, traversal and malformed corpus");
                    affected.Add("verified original deletion refuses on any mismatch");
                    affected.Add("cryptographic erase ordering and hard-link refusal");
                    affected.Add("descriptor identity");
                    affected.Add("symlink rejection");
                    affected.Add("archive-input symlink rejection");
                    affected.Add("container-private archive-input snapshot");
                    affected.Add("overlapping archive-input normalization");
                    affected.Add("descriptor-bound private snapshot");
                }
                if (file.Contains("RecoveryService") || file.Contains("Kpar2"))
                {
                    matched = true;
                    affected.Add("KPAR2-v3 repair, authentication and transplantation rejection");
                    affected.Add("KPAR2-v3 accepts every catalogued suite, not just the first two");
                }
                if (file.Contains("MainWindow") || file.Contains("MacGuiTests") || file.Contains("Avalonia"))
                {
                    matched = true;
                    affected.Add("GUI entropy display beyond the 512 minimum");
                    affected.Add("GUI encryption toggle and target normalization");
                    affected.Add("GUI folder target lands beside the folder");
                    affected.Add("GUI password policy feedback");
                    affected.Add("GUI verified-original-deletion localization");
                    affected.Add("GUI reference control inventory");
                    affected.Add("GUI 256-character factor normalization and field handling");
                    affected.Add("GUI secret clearing wipes password, PIN, and factors");
                    affected.Add("GUI KDF and entropy profile description localization");
                    affected.Add("GUI full creation flow with mouse sampling and factor generation");
                }
                if (file.Contains("QrCodeScanner") || file.Contains("QR-Scanner") || file.Contains("Verify-QR-Scanner"))
                {
                    matched = true;
                    affected.Add("the companion QR scanner is checked against the pinned keys");
                    affected.Add("release companion version plumbing");
                }
                if (file.Contains("Packaging") || file.Contains("HybridSigner") || file.Contains("Integrity"))
                {
                    matched = true;
                    affected.Add("signed native trust and tamper rejection");
                    affected.Add("every Mach-O in the release bundle carries a hybrid signature");
                    affected.Add("ML-DSA-87 managed/reference interoperability");
                }
                if (file.Contains("Threefish") || file.Contains("Kalyna") || file.Contains("Sha3") || file.Contains("Skein") || file.Contains("Mars") || file.Contains("Shacal"))
                {
                    matched = true;
                    affected.Add("SHA3, Skein, Kalyna and Threefish reference vectors");
                    affected.Add("cascade layering: the outer layer alone reveals nothing");
                    affected.Add("v10 two-round key derivation from one pool consumption");
                    affected.Add("salt and nonce for every single-round suite without prepared entropy");
                    affected.Add("v10 per-chunk nonces across a multi-chunk archive");
                    affected.Add("MARS and SHACAL-2 published vectors and CTR behaviour");
                    affected.Add("randomised differential testing against every reference library");
                }

                if (!matched && !IsBenignFile(file))
                {
                    affected.Add("ALL_SMOKE");
                    affected.Add("ALL_COMPREHENSIVE");
                }
            }
            return affected;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsBenignFile(string file)
    {
        string normalized = file.Replace('\\', '/');

        // Explicit root documentation / licensing
        if (string.Equals(normalized, "README.md", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "LICENSE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "LICENSE.txt", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "NOTICE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "NOTICE.txt", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".gitignore", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".gitattributes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".editorconfig", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Dedicated documentation directories
        if (normalized.StartsWith("docs/", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("Documentation/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Purely visual graphic assets
        if (normalized.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".icns", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".ico", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static Dictionary<string, double> LoadTimings(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                string json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<Dictionary<string, double>>(json) ?? [];
            }
        }
        catch
        {
        }
        return [];
    }

    private static void SaveTimings(string path, ConcurrentDictionary<string, double> timings)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            string json = JsonSerializer.Serialize(new Dictionary<string, double>(timings), new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch
        {
        }
    }

    private static void DumpKeySheets(string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string first = string.Concat(Enumerable.Range(0, 256).Select(i => "0123456789abcdef"[(i * 7) % 16]));
        string second = string.Concat(Enumerable.Range(0, 256).Select(i => "0123456789abcdef"[(i * 11 + 3) % 16]));
        foreach (bool english in new[] { false, true })
        {
            var service = new KalynaArchiver.Services.KeySheetService();
            string suffix = english ? "en" : "de";
            string firstTarget = Path.Combine(outputDirectory, $"key-sheet-a-{suffix}.pdf");
            string secondTarget = Path.Combine(outputDirectory, $"key-sheet-b-{suffix}.pdf");
            service.SaveTestPdf(
                new KalynaArchiver.Services.KeySheetData(
                    Path.Combine(outputDirectory, "beispiel-archiv.kzpaq"),
                    KalynaArchiver.Services.EncryptionSuite.ParanoiaCascade,
                    first,
                    second,
                    DateTime.Now,
                    english,
                    string.Empty),
                firstTarget,
                secondTarget);
            Console.WriteLine($"key_sheets={firstTarget}");
            Console.WriteLine($"key_sheets={secondTarget}");
        }
    }
}
