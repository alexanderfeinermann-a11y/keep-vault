using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ComboBox = System.Windows.Controls.ComboBox;
using Button = System.Windows.Controls.Button;
using Orientation = System.Windows.Controls.Orientation;
using StackPanel = System.Windows.Controls.StackPanel;
using TextBlock = System.Windows.Controls.TextBlock;
using Border = System.Windows.Controls.Border;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Brush = System.Windows.Media.Brush;

namespace KalynaArchiver.Gui;

/// <summary>
/// Asks which verified physical printer the key sheets go to.
/// </summary>
/// <remarks>
/// The system print dialog is deliberately not used here. It offers every
/// installed queue, including "Microsoft Print to PDF" and any renamed virtual
/// destination, so refusing those afterwards means the user was first invited
/// to send a 512-bit key to a file. This dialog can only offer queues the
/// spooler gave physical-device evidence for, which is the same rule the macOS
/// build applies to its CUPS destinations.
/// </remarks>
internal sealed class PrinterSelectionDialog : Window
{
    private readonly ComboBox _printers;

    private PrinterSelectionDialog(
        string title,
        IReadOnlyList<string> printers,
        string printText,
        string cancelText)
    {
        Title = title;
        Width = 480;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = (Brush)new BrushConverter().ConvertFromString("#0B1422")!;

        _printers = new ComboBox
        {
            ItemsSource = printers,
            SelectedIndex = 0,
            MinHeight = 32,
            Margin = new Thickness(0, 14, 0, 14),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        var cancel = new Button
        {
            Content = cancelText,
            MinWidth = 100,
            MinHeight = 32,
            Margin = new Thickness(0, 0, 8, 0),
            IsCancel = true,
        };
        cancel.Click += (_, _) =>
        {
            Selected = null;
            DialogResult = false;
        };

        var print = new Button
        {
            Content = printText,
            MinWidth = 100,
            MinHeight = 32,
            IsDefault = true,
        };
        print.Click += (_, _) =>
        {
            Selected = _printers.SelectedItem as string;
            DialogResult = Selected is not null;
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Children = { cancel, print },
        };

        var heading = new TextBlock
        {
            Text = title,
            Foreground = (Brush)new BrushConverter().ConvertFromString("#E8EEF6")!,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        };

        Content = new Border
        {
            Padding = new Thickness(22),
            Child = new StackPanel { Children = { heading, _printers, buttons } },
        };

        Loaded += (_, _) => _printers.Focus();
    }

    internal string? Selected { get; private set; }

    internal static string? Show(
        Window owner,
        string title,
        IReadOnlyList<string> printers,
        string printText,
        string cancelText)
    {
        ArgumentNullException.ThrowIfNull(printers);
        if (printers.Count == 0)
        {
            return null;
        }

        var dialog = new PrinterSelectionDialog(title, printers, printText, cancelText) { Owner = owner };
        return dialog.ShowDialog() == true ? dialog.Selected : null;
    }
}
