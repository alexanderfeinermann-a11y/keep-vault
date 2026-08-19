using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using AppLanguage = QrScanner.Language;

namespace QrScanner;

/// <summary>
/// The window, and everything arranged so a scanned value does not reach disk.
/// </summary>
/// <remarks>
/// The scanned value lives in one field and one text box. What is shown is the
/// escaped rendering; what the copy button hands over is the original. The text
/// box has its spell checker off, because the checker learns words into the
/// user's dictionary, and undo history off, because that history is another
/// copy of the value in a place nothing here controls.
///
/// What this app cannot prevent is written down in README.md rather than
/// quietly omitted.
/// </remarks>
internal sealed class MainWindow : Window
{
    private static readonly Brush PageBackground = Brush("#0B1422");
    private static readonly Brush Panel = Brush("#111C2E");
    private static readonly Brush Ink = Brush("#E8EEF6");
    private static readonly Brush Muted = Brush("#94A3B8");
    private static readonly Brush Good = Brush("#B7F7DE");
    private static readonly Brush Warn = Brush("#FBBF24");
    private static readonly Brush Bad = Brush("#FCA5A5");

    private readonly ComboBox _languageBox = new() { Width = 130 };
    private readonly Image _preview = new() { Stretch = Stretch.Uniform, MinHeight = 240 };
    private readonly TextBlock _statusText = new() { TextWrapping = TextWrapping.Wrap, Foreground = Muted };
    private readonly TextBlock _noticesText = new() { TextWrapping = TextWrapping.Wrap, Foreground = Warn };
    private readonly TextBlock _valueLabel = new() { Foreground = Muted, Margin = new Thickness(0, 12, 0, 4) };
    private readonly TextBox _valueBox;
    private readonly Button _copyButton = new() { MinWidth = 120, IsEnabled = false };
    private readonly Button _rescanButton = new() { MinWidth = 120, IsEnabled = false };
    private readonly VolatileClipboard _clipboard = new();

    private ScanSession? _session;
    private AppLanguage _language = Strings.FromCurrentCulture();
    private ScanOutcome? _outcome;
    private ScannerFailure? _failure;
    private string? _payload;
    private bool _copied;
    private bool _cleared;

    internal MainWindow()
    {
        _valueBox = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinHeight = 96,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 14,
            Background = Panel,
            Foreground = Ink,
            BorderBrush = Brush("#334155"),

            // The checker writes learned words into the user's dictionary, and
            // undo keeps its own copy of everything that was ever in the box.
            // Both are places a scanned factor would outlive this window.
            SpellCheck = { IsEnabled = false },
            IsUndoEnabled = false,
            MaxLength = PayloadInspector.MaximumLength,
        };
        DataObject.AddCopyingHandler(_valueBox, OnValueBoxCopying);

        Title = Strings.For(_language).WindowTitle;
        Width = 720;
        Height = 720;
        MinWidth = 520;
        MinHeight = 560;
        Background = PageBackground;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        _languageBox.Items.Add(new ComboBoxItem { Content = Strings.OwnName(AppLanguage.German), Tag = AppLanguage.German });
        _languageBox.Items.Add(new ComboBoxItem { Content = Strings.OwnName(AppLanguage.English), Tag = AppLanguage.English });
        _languageBox.SelectedIndex = _language == AppLanguage.German ? 0 : 1;
        _languageBox.SelectionChanged += (_, _) =>
        {
            if (_languageBox.SelectedItem is ComboBoxItem { Tag: AppLanguage selected })
            {
                _language = selected;
                ApplyLanguage();
            }
        };

        _copyButton.Click += (_, _) => CopyPayload();
        _rescanButton.Click += (_, _) => Rescan();

        Content = BuildLayout();
        ApplyLanguage();

        Loaded += async (_, _) => await StartAsync();
        Closed += async (_, _) => await ShutDownAsync();
    }

    private UIElement BuildLayout()
    {
        var languageRow = new DockPanel { LastChildFill = false, Margin = new Thickness(0, 0, 0, 12) };
        var languageLabel = new TextBlock
        {
            Name = "LanguageLabel",
            Foreground = Muted,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
        };
        DockPanel.SetDock(languageLabel, Dock.Left);
        DockPanel.SetDock(_languageBox, Dock.Left);
        languageRow.Children.Add(languageLabel);
        languageRow.Children.Add(_languageBox);
        RegisterName("LanguageLabel", languageLabel);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 12, 0, 0),
        };
        _copyButton.Margin = new Thickness(0, 0, 8, 0);
        buttons.Children.Add(_copyButton);
        buttons.Children.Add(_rescanButton);

        var stack = new StackPanel { Margin = new Thickness(18) };
        stack.Children.Add(languageRow);
        stack.Children.Add(new Border
        {
            Background = Panel,
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(6),
            Child = _preview,
        });
        _statusText.Margin = new Thickness(0, 12, 0, 0);
        stack.Children.Add(_statusText);
        _noticesText.Margin = new Thickness(0, 6, 0, 0);
        stack.Children.Add(_noticesText);
        stack.Children.Add(_valueLabel);
        stack.Children.Add(_valueBox);
        stack.Children.Add(buttons);

        return new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Content = stack,
        };
    }

    private async Task StartAsync()
    {
        _statusText.Text = Strings.For(_language).RequestingCamera;
        var session = new ScanSession(SynchronizationContext.Current
            ?? throw new InvalidOperationException("The window has no dispatcher context."));
        session.Observed += OnObserved;
        session.Failed += OnFailed;
        session.PreviewUpdated += frame => _preview.Source = frame;
        _session = session;
        await session.StartAsync();
        if (_failure is null)
        {
            _outcome = ScanOutcome.Searching;
            ApplyLanguage();
        }
    }

    private async Task ShutDownAsync()
    {
        // The value goes before the window does, and the clipboard entry with
        // it: a scan left on the clipboard because the window was closed early
        // is the one case the expiry timer cannot cover.
        _payload = null;
        _valueBox.Clear();
        _clipboard.ClearIfStillOurs();
        _clipboard.Dispose();

        ScanSession? session = _session;
        _session = null;
        if (session is not null)
        {
            await session.DisposeAsync();
        }
    }

    private void OnObserved(ScanOutcome outcome)
    {
        _outcome = outcome;
        _failure = null;

        if (outcome.Kind == ScanOutcomeKind.Accepted && outcome.Payload is { Length: > 0 } payload)
        {
            _payload = payload;
            _copied = false;
            _cleared = false;
            _valueBox.Text = PayloadInspector.DisplayText(payload);
            _copyButton.IsEnabled = true;
            _rescanButton.IsEnabled = true;

            // Stop decoding while a result is on screen, so a second code
            // drifting into view cannot silently replace what the user is
            // looking at.
            _session?.Suspend();
        }

        ApplyLanguage();
    }

    private void OnFailed(ScannerFailure failure)
    {
        _failure = failure;
        _outcome = null;
        ApplyLanguage();
    }

    private void CopyPayload()
    {
        if (_payload is not { Length: > 0 } payload)
        {
            return;
        }

        _clipboard.Copy(payload, () =>
        {
            _cleared = true;
            _copied = false;
            ApplyLanguage();
        });
        _copied = true;
        _cleared = false;
        ApplyLanguage();
    }

    private void Rescan()
    {
        _payload = null;
        _copied = false;
        _cleared = false;
        _valueBox.Clear();
        _copyButton.IsEnabled = false;
        _rescanButton.IsEnabled = false;
        _clipboard.ClearIfStillOurs();
        _outcome = ScanOutcome.Searching;
        _session?.Resume();
        ApplyLanguage();
    }

    /// <summary>
    /// Copying out of the text box must hand over the payload, not its escaped
    /// rendering.
    /// </summary>
    /// <remarks>
    /// The box shows control characters as their code points so the user can
    /// see what is there. Ctrl+C would otherwise transfer that rendering, which
    /// is not what the code contained - and for a hex factor a silently altered
    /// value is a factor that will not open the archive.
    /// </remarks>
    private void OnValueBoxCopying(object sender, DataObjectCopyingEventArgs e)
    {
        if (_payload is not { Length: > 0 })
        {
            return;
        }

        e.Handled = true;
        e.CancelCommand();
        CopyPayload();
    }

    private void ApplyLanguage()
    {
        Strings strings = Strings.For(_language);
        Title = strings.WindowTitle;
        ((TextBlock)FindName("LanguageLabel")).Text = strings.LanguageLabel;
        _copyButton.Content = strings.CopyButton;
        _rescanButton.Content = strings.RescanButton;
        _valueLabel.Text = strings.ScannedValueLabel;

        if (_failure is { } failure)
        {
            _statusText.Text = failure.Kind == ScannerFailureKind.AccessDenied
                ? $"{failure.Message(strings)} {strings.CameraDeniedHint}"
                : failure.Message(strings);
            _statusText.Foreground = Bad;
            _noticesText.Text = string.Empty;
            return;
        }

        if (_cleared)
        {
            _statusText.Text = strings.ClipboardCleared;
            _statusText.Foreground = Warn;
        }
        else if (_copied)
        {
            _statusText.Text = strings.Copied((int)_clipboard.Lifetime.TotalSeconds);
            _statusText.Foreground = Good;
        }
        else if (_outcome is { } outcome)
        {
            _statusText.Text = strings.Describe(outcome);
            _statusText.Foreground = outcome.Kind switch
            {
                ScanOutcomeKind.Accepted => Good,
                ScanOutcomeKind.Conflict => Bad,
                _ => Muted,
            };
        }
        else
        {
            _statusText.Text = strings.RequestingCamera;
            _statusText.Foreground = Muted;
        }

        _noticesText.Text = _payload is { Length: > 0 } payload
            ? string.Join(" ", PayloadInspector.Notices(payload).Select(notice => notice.Message(strings)))
            : string.Empty;
    }

    private static Brush Brush(string color)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(color)!;
        brush.Freeze();
        return brush;
    }
}
