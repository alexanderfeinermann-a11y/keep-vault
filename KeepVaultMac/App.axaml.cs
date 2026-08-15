using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace KalynaArchiver;

public sealed partial class App : Application
{
    private MainWindow? _mainWindow;
    private IActivatableLifetime? _activatableLifetime;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _mainWindow = new MainWindow();
            desktop.MainWindow = _mainWindow;
            desktop.Exit += Desktop_Exit;
        }

        if (ApplicationLifetime is IActivatableLifetime activatableLifetime)
        {
            _activatableLifetime = activatableLifetime;
            activatableLifetime.Activated += ActivatableLifetime_Activated;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ActivatableLifetime_Activated(object? sender, ActivatedEventArgs e)
    {
        if (e is not FileActivatedEventArgs fileActivation)
        {
            return;
        }

        IStorageItem[] items = fileActivation.Files.ToArray();
        if (Dispatcher.UIThread.CheckAccess())
        {
            ActivateFirstArchive(items);
        }
        else
        {
            Dispatcher.UIThread.Post(() => ActivateFirstArchive(items));
        }
    }

    private void ActivateFirstArchive(IReadOnlyList<IStorageItem> items)
    {
        bool accepted = false;
        foreach (IStorageItem item in items)
        {
            if (!accepted
                && item is IStorageFile file
                && _mainWindow is not null
                && _mainWindow.HandleFileActivation(file))
            {
                accepted = true;
                continue;
            }

            item.Dispose();
        }
    }

    private void Desktop_Exit(object? sender, ControlledApplicationLifetimeExitEventArgs e)
    {
        if (_activatableLifetime is not null)
        {
            _activatableLifetime.Activated -= ActivatableLifetime_Activated;
            _activatableLifetime = null;
        }

        _mainWindow = null;
    }
}
