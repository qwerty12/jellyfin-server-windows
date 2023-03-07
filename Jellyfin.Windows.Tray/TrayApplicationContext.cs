using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.Win32;

namespace Jellyfin.Windows.Tray;

/// <summary>
/// Tray application context.
/// </summary>
public class TrayApplicationContext : ApplicationContext
{
    private const string TrayIconResourceName = "Jellyfin.Windows.Tray.Resources.JellyfinIcon.ico";
    private readonly string _jellyfinServiceName = "JellyfinServer";
    private readonly string _autostartKey = "JellyfinTray";
    private string _configFile;
    private string _networkFile;
    private string _port;
    private bool _firstRunDone = false;
    private string _networkAddress;
    private string _executableFile;
    private string _dataFolder = @"C:\ProgramData\Jellyfin\Server";
    private string _localJellyfinUrl = "http://127.0.0.1:8096/web/index.html";
    private NotifyIcon _trayIcon;
    private ServiceController _serviceController;
    private ToolStripMenuItem _menuItemAutostart;
    private ToolStripMenuItem _menuItemStart;
    private ToolStripMenuItem _menuItemStop;
    private ToolStripMenuItem _menuItemOpen;
    private ToolStripMenuItem _menuItemLogFolder;
    private ToolStripMenuItem _menuItemExit;
    private string _installFolder;
    private RunType _runType;
    private Process _jellyfinProcess;

    /// <summary>
    /// Initializes a new instance of the <see cref="TrayApplicationContext"/> class.
    /// </summary>
    public TrayApplicationContext()
    {
        _serviceController = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == _jellyfinServiceName);
        if (_serviceController != null)
        {
            _runType = RunType.Service;
        }

        if (_serviceController == null)
        {
            try
            {
                LoadJellyfinConfig();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message + "\r\nCouldn't find Jellyfin Installation. The application will now close.");
                Application.Exit();
                return;
            }

            _runType = RunType.Executable;
        }

        CreateTrayIcon();

        if (!_firstRunDone)
        {
            CheckShowServiceNotElevatedWarning();
            AutoStart = true;
        }
        else
        {
            _firstRunDone = true;
        }

        if (_runType == RunType.Executable)
        {
            // check if Jellyfin is already running, if not, start it
            foreach (Process p in Process.GetProcessesByName("jellyfin"))
            {
                if (_jellyfinProcess is null && p.MainModule?.FileName.Equals(_executableFile, StringComparison.Ordinal) == true)
                {
                    _jellyfinProcess = p;
                    _jellyfinProcess.EnableRaisingEvents = true;
                    _jellyfinProcess.Exited += JellyfinExited;
                    continue;
                }

                p.Dispose();
            }

            if (_jellyfinProcess is null)
            {
                Start(null, null);
            }
        }
    }

    private bool AutoStart
    {
        get
        {
            using RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            return key.GetValue(_autostartKey) != null;
        }

        set
        {
            using RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            if (value && key.GetValue(_autostartKey) == null)
            {
                key.SetValue(_autostartKey, Path.ChangeExtension(Application.ExecutablePath, "exe"));
            }
            else if (!value && key.GetValue(_autostartKey) != null)
            {
                key.DeleteValue(_autostartKey);
            }
        }
    }

    private void JellyfinExited(object sender, EventArgs e)
    {
        if (_jellyfinProcess is not null)
        {
            _jellyfinProcess.Dispose();
            _jellyfinProcess = null;
        }
    }

    private void CreateTrayIcon()
    {
        _menuItemAutostart = new ToolStripMenuItem("Autostart", null, AutoStartToggle);
        _menuItemStart = new ToolStripMenuItem("Start Jellyfin", null, Start);
        _menuItemStop = new ToolStripMenuItem("Stop Jellyfin", null, Stop);
        _menuItemOpen = new ToolStripMenuItem("Open Jellyfin", null, Open);
        _menuItemLogFolder = new ToolStripMenuItem("Show Logs", null, ShowLogs);
        _menuItemExit = new ToolStripMenuItem("Exit", null, Exit);

        ContextMenuStrip contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add(_menuItemAutostart);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(_menuItemStart);
        contextMenu.Items.Add(_menuItemStop);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(_menuItemOpen);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(_menuItemLogFolder);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(_menuItemExit);

        contextMenu.Opening += new CancelEventHandler(ContextMenuOnPopup);
        using var iconStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(TrayIconResourceName);
        _trayIcon = new NotifyIcon() { Icon = new Icon(iconStream), ContextMenuStrip = contextMenu, Visible = true, Text = "Jellyfin" };
        _trayIcon.DoubleClick += Open;
    }

    private void LoadJellyfinConfig()
    {
        RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\WOW6432Node\\Jellyfin\\Server");
        _installFolder = registryKey.GetValue("InstallFolder").ToString();
        _dataFolder = registryKey.GetValue("DataFolder").ToString();
        _configFile = Path.Combine(_dataFolder, "config\\system.xml").ToString();
        _networkFile = Path.Combine(_dataFolder, "config\\network.xml").ToString();
        _executableFile = Path.Combine(_installFolder, "jellyfin.exe");

        if (File.Exists(_configFile))
        {
            XDocument systemXml = XDocument.Load(_configFile);
            XPathNavigator settingsReader = systemXml.CreateNavigator();

            _firstRunDone = settingsReader.SelectSingleNode("/ServerConfiguration/IsStartupWizardCompleted").ValueAsBoolean;
        }

        if (File.Exists(_networkFile))
        {
            XDocument networkXml = XDocument.Load(_networkFile);
            XPathNavigator networkReader = networkXml.CreateNavigator();

            _networkAddress = networkReader.SelectSingleNode("/NetworkConfiguration/LocalNetworkAddresses").Value;
            _port = networkReader.SelectSingleNode("/NetworkConfiguration/HttpServerPortNumber")?.Value;
        }

        if (string.IsNullOrEmpty(_port))
        {
            _port = "8096";
        }

        if (string.IsNullOrEmpty(_networkAddress))
        {
            _networkAddress = "127.0.0.1";
        }

        _localJellyfinUrl = "http://" + _networkAddress + ":" + _port + "/web/index.html";
    }

    private bool CheckShowServiceNotElevatedWarning()
    {
        if (_runType == RunType.Service && !IsElevated())
        {
            MessageBox.Show("When running Jellyfin as a service, the tray application must be run as Administrator.");
            return true;
        }

        return false;
    }

    private bool IsElevated()
    {
        WindowsIdentity id = WindowsIdentity.GetCurrent();
        return id.Owner != id.User;
    }

    private void AutoStartToggle(object sender, EventArgs e)
    {
        AutoStart = !AutoStart;
    }

    private void Open(object sender, EventArgs e)
    {
        Process.Start(new ProcessStartInfo(_localJellyfinUrl) { UseShellExecute = true });
    }

    private void ShowLogs(object sender, EventArgs e)
    {
        Process.Start(new ProcessStartInfo(_dataFolder + "\\log") { UseShellExecute = true });
    }

    private void ContextMenuOnPopup(object sender, EventArgs e)
    {
        bool runningAsService = _runType == RunType.Service;
        bool exeRunning = false;
        if (runningAsService)
        {
            _serviceController.Refresh();
        }
        else
        {
            exeRunning = _jellyfinProcess is not null;
        }

        bool running = (!runningAsService && exeRunning) || (runningAsService && _serviceController.Status == ServiceControllerStatus.Running);
        bool stopped = (!runningAsService && !exeRunning) || (runningAsService && _serviceController.Status == ServiceControllerStatus.Stopped);
        _menuItemStart.Enabled = stopped;
        _menuItemStop.Enabled = running;
        _menuItemOpen.Enabled = running;
        _menuItemAutostart.Checked = AutoStart;
    }

    private void Start(object sender, EventArgs e)
    {
        if (_runType == RunType.Service)
        {
            if (CheckShowServiceNotElevatedWarning())
            {
                return;
            }

            _serviceController.Start();
        }
        else if (_jellyfinProcess is null)
        {
            Process p = new Process();
            p.StartInfo.FileName = _executableFile;
            p.StartInfo.WorkingDirectory = _installFolder;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.Arguments = "--datadir \"" + _dataFolder + "\"";
            p.EnableRaisingEvents = true;
            p.Exited += JellyfinExited;
            if (p.Start())
            {
                _jellyfinProcess = p;
            }
        }
    }

    private void Stop(object sender, EventArgs e)
    {
        if (_runType == RunType.Service)
        {
            if (CheckShowServiceNotElevatedWarning())
            {
                return;
            }

            _serviceController.Stop();
        }
        else if (_jellyfinProcess is not null)
        {
            if (!_jellyfinProcess.CloseMainWindow())
            {
                _jellyfinProcess.Kill();
            }
        }
    }

    private void Exit(object sender, EventArgs e)
    {
        if (_runType == RunType.Executable)
        {
            Stop(null, null);
        }

        _trayIcon.Visible = false;
        Application.Exit();
    }
}
