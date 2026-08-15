using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace KalynaArchiver.Gui;

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
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowDecorations = WindowDecorations.Full;
        ShowInTaskbar = false;
        Background = Brush.Parse("#0B1422");

        _printers = new ComboBox
        {
            ItemsSource = printers,
            SelectedIndex = 0,
            MinHeight = 40,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        var cancel = new Button
        {
            Content = cancelText,
            MinWidth = 100,
            MinHeight = 38,
            Background = Brush.Parse("#17263A"),
            Foreground = Brush.Parse("#E8EEF6"),
        };
        cancel.Click += (_, _) => Close(null);

        var print = new Button
        {
            Content = printText,
            MinWidth = 100,
            MinHeight = 38,
            Background = Brush.Parse("#B7F7DE"),
            Foreground = Brush.Parse("#092A20"),
        };
        print.Click += (_, _) => Close(_printers.SelectedItem as string);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Children = { cancel, print },
        };
        Grid.SetRow(buttons, 2);

        var heading = new TextBlock
        {
            Text = title,
            Foreground = Brush.Parse("#E8EEF6"),
            FontSize = 18,
            FontWeight = FontWeight.SemiBold,
        };
        Grid.SetRow(_printers, 1);

        Content = new Border
        {
            Padding = new Thickness(22),
            Child = new Grid
            {
                RowDefinitions = new RowDefinitions("Auto,Auto,Auto"),
                RowSpacing = 14,
                Children = { heading, _printers, buttons },
            },
        };
        Opened += (_, _) => _printers.Focus();
    }

    internal static Task<string?> ShowAsync(
        Window owner,
        string title,
        IReadOnlyList<string> printers,
        string printText,
        string cancelText)
    {
        var dialog = new PrinterSelectionDialog(title, printers, printText, cancelText);
        return dialog.ShowDialog<string?>(owner);
    }
}
