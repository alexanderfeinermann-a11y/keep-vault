using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace KalynaArchiver.Gui;

internal enum SecurityDialogKind
{
    Information,
    Warning,
    Error,
    DestructiveConfirmation,
}

internal sealed class SecurityDialog : Window
{
    private SecurityDialog(
        string title,
        string message,
        string acceptText,
        string cancelText,
        SecurityDialogKind kind)
    {
        Title = title;
        Width = 520;
        MinWidth = 420;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brush.Parse("#0B1422");
        WindowDecorations = WindowDecorations.Full;
        ShowInTaskbar = false;

        bool confirmation = kind == SecurityDialogKind.DestructiveConfirmation;
        IBrush accent = kind switch
        {
            SecurityDialogKind.Error => Brush.Parse("#F29AA6"),
            SecurityDialogKind.Warning or SecurityDialogKind.DestructiveConfirmation => Brush.Parse("#F2BD55"),
            _ => Brush.Parse("#5DE4EC"),
        };

        var accept = new Button
        {
            Content = acceptText,
            MinWidth = 105,
            MinHeight = 38,
            Padding = new Thickness(16, 8),
            CornerRadius = new CornerRadius(9),
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Background = confirmation ? Brush.Parse("#A33A4B") : Brush.Parse("#5DE4EC"),
            Foreground = confirmation ? Brushes.White : Brush.Parse("#04121B"),
            BorderBrush = confirmation ? Brush.Parse("#D65D6E") : Brush.Parse("#43D8E5"),
            BorderThickness = new Thickness(1),
            FontWeight = FontWeight.SemiBold,
        };
        accept.Click += (_, _) => Close(true);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Children = { accept },
        };

        if (confirmation)
        {
            var cancel = new Button
            {
                Content = cancelText,
                MinWidth = 105,
                MinHeight = 38,
                Padding = new Thickness(16, 8),
                CornerRadius = new CornerRadius(9),
                Background = Brush.Parse("#17263A"),
                Foreground = Brush.Parse("#E8EEF6"),
                BorderBrush = Brush.Parse("#31445D"),
                BorderThickness = new Thickness(1),
                FontWeight = FontWeight.SemiBold,
            };
            cancel.Click += (_, _) => Close(false);
            buttons.Children.Insert(0, cancel);
        }

        Content = new Border
        {
            Padding = new Thickness(22),
            Child = new Grid
            {
                RowDefinitions = new RowDefinitions("Auto,Auto,Auto"),
                RowSpacing = 15,
                Children =
                {
                    new Border
                    {
                        Width = 46,
                        Height = 5,
                        CornerRadius = new CornerRadius(3),
                        Background = accent,
                        HorizontalAlignment = HorizontalAlignment.Left,
                    },
                    new TextBlock
                    {
                        [Grid.RowProperty] = 1,
                        Text = message,
                        Foreground = Brush.Parse("#E8EEF6"),
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 14,
                        MaxWidth = 470,
                    },
                    buttons.WithGridRow(2),
                },
            },
        };

        Opened += (_, _) => accept.Focus();
    }

    internal static Task<bool> ShowAsync(
        Window owner,
        string title,
        string message,
        string acceptText,
        string cancelText,
        SecurityDialogKind kind)
    {
        var dialog = new SecurityDialog(title, message, acceptText, cancelText, kind);
        return dialog.ShowDialog<bool>(owner);
    }
}

internal static class SecurityDialogGridExtensions
{
    internal static T WithGridRow<T>(this T control, int row) where T : Control
    {
        Grid.SetRow(control, row);
        return control;
    }
}
