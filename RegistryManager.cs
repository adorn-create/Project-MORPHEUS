using System;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace ThreatGuard.Setup
{
    [SupportedOSPlatform("windows")]
    public static class RegistryManager
    {
        private const string UninstallRegistryPath =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        private const string ProductDisplayName = "Morpheus Defense";
        private static readonly RegistryView[] RegistryViews =
        {
            RegistryView.Registry64,
            RegistryView.Registry32
        };

        public static bool IsMorpheusRegistered()
        {
            foreach (RegistryHive hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                foreach (RegistryView view in RegistryViews)
                {
                    using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
                    using (RegistryKey? uninstallRoot =
                        baseKey.OpenSubKey(UninstallRegistryPath, writable: false))
                    {
                        if (uninstallRoot == null)
                        {
                            continue;
                        }

                        foreach (string subKeyName in uninstallRoot.GetSubKeyNames())
                        {
                            using (RegistryKey? entry =
                                uninstallRoot.OpenSubKey(subKeyName, writable: false))
                            {
                                if (entry == null)
                                {
                                    continue;
                                }

                                string? displayName = entry.GetValue("DisplayName") as string;
                                string? uninstallString = entry.GetValue("UninstallString") as string;
                                if (string.Equals(
                                        displayName,
                                        ProductDisplayName,
                                        StringComparison.OrdinalIgnoreCase)
                                    && !string.IsNullOrWhiteSpace(uninstallString))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public static void OpenAppsAndFeatures()
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "ms-settings:appsfeatures",
                UseShellExecute = true
            });
        }
    }
}
