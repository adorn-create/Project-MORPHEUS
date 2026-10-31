using System;
using System.ComponentModel;
using System.Drawing;
using System.Security;
using System.Windows.Forms;
using ThreatGuard.Setup;

namespace Morpheus.Uninstaller
{
    public sealed class MainForm : Form
    {
        private readonly Label statusLabel;

        public MainForm()
        {
            Text = "Morpheus Defense - Uninstall Help";
            ClientSize = new Size(520, 265);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(15, 23, 42);
            ForeColor = Color.FromArgb(226, 232, 240);
            Font = new Font("Segoe UI", 10F);

            var titleLabel = new Label
            {
                AutoSize = true,
                Left = 24,
                Top = 22,
                Font = new Font("Segoe UI Semibold", 18F),
                ForeColor = Color.White,
                Text = "Uninstall Morpheus Defense"
            };
            var explanationLabel = new Label
            {
                Left = 26,
                Top = 70,
                Width = 465,
                Height = 48,
                ForeColor = Color.FromArgb(203, 213, 225),
                Text = "Windows manages removal so you stay in control. This helper does not delete files or change system settings."
            };
            statusLabel = new Label
            {
                Left = 26,
                Top = 126,
                Width = 465,
                Height = 36,
                ForeColor = Color.FromArgb(147, 197, 253),
                Text = GetRegistrationStatus()
            };
            var openSettingsButton = new Button
            {
                Text = "Open Windows Apps settings",
                Left = 26,
                Top = 183,
                Width = 250,
                Height = 42,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                UseVisualStyleBackColor = false
            };
            openSettingsButton.FlatAppearance.BorderSize = 0;
            openSettingsButton.Click += OpenSettings;

            Controls.Add(titleLabel);
            Controls.Add(explanationLabel);
            Controls.Add(statusLabel);
            Controls.Add(openSettingsButton);
        }

        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        private static string GetRegistrationStatus()
        {
            try
            {
                return RegistryManager.IsMorpheusRegistered()
                    ? "Morpheus Defense is registered with Windows Apps."
                    : "No Morpheus Defense uninstall entry was found.";
            }
            catch (Exception ex) when (
                ex is UnauthorizedAccessException
                || ex is SecurityException
                || ex is System.IO.IOException)
            {
                return $"Could not check the Windows uninstall entry: {ex.Message}";
            }
        }

        private void OpenSettings(object? sender, EventArgs e)
        {
            try
            {
                RegistryManager.OpenAppsAndFeatures();
            }
            catch (Win32Exception ex)
            {
                ShowSettingsError(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                ShowSettingsError(ex.Message);
            }
        }

        private void ShowSettingsError(string message)
        {
            MessageBox.Show(
                this,
                $"Windows Apps settings could not be opened: {message}",
                "Unable to open uninstall settings",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
