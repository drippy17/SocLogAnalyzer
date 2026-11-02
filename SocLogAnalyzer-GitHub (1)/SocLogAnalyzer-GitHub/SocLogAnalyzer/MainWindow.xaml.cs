
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Win32;
using SkiaSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SocLogAnalyzer
{
    public partial class MainWindow : Window
    {
        private List<LogEntry> loadedLogs = new List<LogEntry>();
        private List<SecurityAlert> detectedAlerts = new List<SecurityAlert>();

        private readonly InvestigationStorage investigationStorage =
            new InvestigationStorage();

        private bool hasAnalyzedLogs = false;

        public MainWindow()
        {
            InitializeComponent();

            UpdateDashboard();
            UpdateSystemStatus();
        }

        private string GetAlertKey(SecurityAlert alert)
        {
            return $"{alert.Timestamp:O}|{alert.Username}|{alert.IPAddress}|{alert.FailedAttempts}|{alert.Severity}";
        }

        // DASHBOARD NAVIGATION: NEVER CLEARS THE WORKSPACE
        private void DashboardButton_Click(object sender, RoutedEventArgs e)
        {
            UpdateDashboard();
            UpdateSystemStatus();

            StatusText.Text = loadedLogs.Count == 0
                ? "Dashboard ready. Import a security log file to begin."
                : $"Dashboard ready. {loadedLogs.Count} log event(s) loaded and {detectedAlerts.Count} alert(s) detected.";
        }

        // OPEN THE DETECTION RULES WINDOW
        private void DetectionRulesButton_Click(object sender, RoutedEventArgs e)
        {
            DetectionRulesWindow rulesWindow = new DetectionRulesWindow();
            rulesWindow.Owner = this;
            rulesWindow.ShowDialog();
        }

        // DYNAMIC SYSTEM STATUS
        private void UpdateSystemStatus()
        {
            if (loadedLogs.Count == 0)
            {
                SystemStatusText.Text = "● WAITING FOR LOGS";
                SystemStatusText.Foreground =
                    new SolidColorBrush(Color.FromRgb(203, 213, 225));

                SystemStatusBorder.Background =
                    new SolidColorBrush(Color.FromRgb(30, 41, 59));

                SystemStatusBorder.BorderBrush =
                    new SolidColorBrush(Color.FromRgb(71, 85, 105));
            }
            else if (!hasAnalyzedLogs)
            {
                SystemStatusText.Text = "● LOGS LOADED";
                SystemStatusText.Foreground =
                    new SolidColorBrush(Color.FromRgb(147, 197, 253));

                SystemStatusBorder.Background =
                    new SolidColorBrush(Color.FromRgb(23, 37, 64));

                SystemStatusBorder.BorderBrush =
                    new SolidColorBrush(Color.FromRgb(37, 99, 235));
            }
            else
            {
                SystemStatusText.Text = "● ANALYSIS COMPLETE";
                SystemStatusText.Foreground =
                    new SolidColorBrush(Color.FromRgb(134, 239, 172));

                SystemStatusBorder.Background =
                    new SolidColorBrush(Color.FromRgb(19, 43, 36));

                SystemStatusBorder.BorderBrush =
                    new SolidColorBrush(Color.FromRgb(22, 101, 52));
            }
        }

        // FILTER LOG EVENTS
        private void FilterLogsButton_Click(object sender, RoutedEventArgs e)
        {
            if (loadedLogs.Count == 0)
            {
                MessageBox.Show(
                    "Please import a log file first.",
                    "No Logs",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            string searchText = LogSearchTextBox.Text.Trim();
            string selectedStatus = "All";

            if (StatusFilterComboBox.SelectedItem is ComboBoxItem item)
            {
                selectedStatus = item.Content?.ToString() ?? "All";
            }

            List<LogEntry> filteredLogs = loadedLogs.Where(log =>
                (string.IsNullOrWhiteSpace(searchText) ||
                 (log.Username ?? "").Contains(
                     searchText, StringComparison.OrdinalIgnoreCase) ||
                 (log.IPAddress ?? "").Contains(
                     searchText, StringComparison.OrdinalIgnoreCase)) &&
                (selectedStatus == "All" ||
                 string.Equals(
                     log.Status,
                     selectedStatus,
                     StringComparison.OrdinalIgnoreCase))
            ).ToList();

            LogDataGrid.ItemsSource = filteredLogs;

            StatusText.Text =
                $"Showing {filteredLogs.Count} matching log event(s).";
        }

        // IMPORT LOG FILE
        private void ImportLogButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Filter = "Log files (*.log;*.txt)|*.log;*.txt|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() != true)
                return;

            try
            {
                LogParser parser = new LogParser();
                loadedLogs = parser.ParseLogFile(dialog.FileName);

                detectedAlerts.Clear();
                hasAnalyzedLogs = false;

                AlertDataGrid.ItemsSource = null;
                PriorityAlertsDataGrid.ItemsSource = null;
                LogDataGrid.ItemsSource = loadedLogs;

                LogSearchTextBox.Clear();
                StatusFilterComboBox.SelectedIndex = 0;

                ResetAlertFilterControls();

                LogData();
                UpdateDashboard();
                UpdateSystemStatus();

                StatusText.Text =
                    $"Loaded {loadedLogs.Count} log events. Click Analyze Logs to scan for threats.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"The log file could not be loaded.\n\n{ex.Message}",
                    "Import Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // ANALYZE LOGS
        private void AnalyzeButton_Click(object sender, RoutedEventArgs e)
        {
            if (loadedLogs.Count == 0)
            {
                MessageBox.Show(
                    "Please import a log file first.",
                    "No Logs",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            try
            {
                DetectionEngine engine = new DetectionEngine();
                detectedAlerts = engine.Analyze(loadedLogs);

                Dictionary<string, InvestigationRecord> savedInvestigations =
                    investigationStorage.LoadInvestigations();

                foreach (SecurityAlert alert in detectedAlerts)
                {
                    string key = GetAlertKey(alert);

                    if (savedInvestigations.TryGetValue(
                        key, out InvestigationRecord savedRecord))
                    {
                        alert.InvestigationStatus =
                            savedRecord.Status ?? "New";

                        alert.InvestigationNotes =
                            savedRecord.Notes ?? "";

                        alert.AssignedAnalyst =
                            savedRecord.AssignedAnalyst ?? "";

                        alert.InvestigationStartedAt =
                            savedRecord.InvestigationStartedAt;

                        alert.ResolvedAt =
                            savedRecord.ResolvedAt;

                        alert.InvestigationHistory =
                            savedRecord.History ??
                            new List<InvestigationHistoryEntry>();
                    }
                    else
                    {
                        alert.InvestigationStatus =
                            string.IsNullOrWhiteSpace(alert.InvestigationStatus)
                                ? "New"
                                : alert.InvestigationStatus;

                        alert.InvestigationNotes ??= "";
                        alert.AssignedAnalyst ??= "";

                        alert.InvestigationHistory ??=
                            new List<InvestigationHistoryEntry>();
                    }
                }

                hasAnalyzedLogs = true;

                ResetAlertFilterControls();
                RefreshAlertList();
                UpdateDashboard();
                UpdateSystemStatus();

                if (detectedAlerts.Count == 0)
                {
                    StatusText.Text =
                        "Analysis complete. No suspicious activity detected.";

                    MessageBox.Show(
                        "No suspicious activity was detected.",
                        "Analysis Complete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    StatusText.Text =
                        $"Analysis complete. {detectedAlerts.Count} security alert(s) detected.";

                    MessageBox.Show(
                        $"{detectedAlerts.Count} security alert(s) detected.",
                        "Security Alert",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Log analysis failed.\n\n{ex.Message}",
                    "Analysis Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // FILTER AND SORT SECURITY ALERTS
        private void FilterAlertsButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshAlertList();

            List<SecurityAlert> visibleAlerts =
                AlertDataGrid.ItemsSource as List<SecurityAlert>
                ?? new List<SecurityAlert>();

            StatusText.Text =
                $"Showing {visibleAlerts.Count} of {detectedAlerts.Count} security alert(s).";
        }

        // APPLY SEARCH, SEVERITY, STATUS AND SORTING
        private void RefreshAlertList()
        {
            string searchText = AlertSearchTextBox.Text.Trim();

            string selectedSeverity = "All Severities";
            string selectedStatus = "All Statuses";
            string selectedSort = "High Severity First";

            if (AlertSeverityFilterComboBox.SelectedItem
                is ComboBoxItem severityItem)
            {
                selectedSeverity =
                    severityItem.Content?.ToString() ?? "All Severities";
            }

            if (AlertStatusFilterComboBox.SelectedItem
                is ComboBoxItem statusItem)
            {
                selectedStatus =
                    statusItem.Content?.ToString() ?? "All Statuses";
            }

            if (AlertSortComboBox.SelectedItem is ComboBoxItem sortItem)
            {
                selectedSort =
                    sortItem.Content?.ToString() ?? "High Severity First";
            }

            IEnumerable<SecurityAlert> query = detectedAlerts.Where(alert =>
                (string.IsNullOrWhiteSpace(searchText) ||
                 (alert.Username ?? "").Contains(
                     searchText, StringComparison.OrdinalIgnoreCase) ||
                 (alert.IPAddress ?? "").Contains(
                     searchText, StringComparison.OrdinalIgnoreCase)) &&

                (selectedSeverity == "All Severities" ||
                 string.Equals(
                     alert.Severity,
                     selectedSeverity,
                     StringComparison.OrdinalIgnoreCase)) &&

                (selectedStatus == "All Statuses" ||
                 string.Equals(
                     alert.InvestigationStatus,
                     selectedStatus,
                     StringComparison.OrdinalIgnoreCase))
            );

            switch (selectedSort)
            {
                case "High Severity First":
                    query = query
                        .OrderBy(alert => GetSeverityRank(alert.Severity))
                        .ThenByDescending(alert => alert.Timestamp);
                    break;

                case "Medium Severity First":
                    query = query
                        .OrderBy(alert => GetMediumFirstSeverityRank(alert.Severity))
                        .ThenByDescending(alert => alert.Timestamp);
                    break;

                case "Newest First":
                    query = query.OrderByDescending(alert => alert.Timestamp);
                    break;

                case "Oldest First":
                    query = query.OrderBy(alert => alert.Timestamp);
                    break;
            }

            AlertDataGrid.ItemsSource = query.ToList();
        }

        // HIGH SEVERITY GETS THE HIGHEST PRIORITY
        private int GetSeverityRank(string severity)
        {
            if (string.Equals(
                severity, "High", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (string.Equals(
                severity, "Medium", StringComparison.OrdinalIgnoreCase))
                return 1;

            return 2;
        }

        // MEDIUM SEVERITY GETS THE HIGHEST PRIORITY
        private int GetMediumFirstSeverityRank(string severity)
        {
            if (string.Equals(
                severity, "Medium", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (string.Equals(
                severity, "High", StringComparison.OrdinalIgnoreCase))
                return 1;

            return 2;
        }

        // RESET ALERT FILTERS
        private void ResetAlertFiltersButton_Click(
            object sender, RoutedEventArgs e)
        {
            ResetAlertFilterControls();
            RefreshAlertList();

            StatusText.Text =
                $"Showing all {detectedAlerts.Count} security alert(s).";
        }

        private void ResetAlertFilterControls()
        {
            AlertSearchTextBox.Clear();
            AlertSeverityFilterComboBox.SelectedIndex = 0;
            AlertStatusFilterComboBox.SelectedIndex = 0;
            AlertSortComboBox.SelectedIndex = 0;
        }

        // UPDATE LOG COUNTERS
        private void LogData()
        {
            TotalLogsText.Text = loadedLogs.Count.ToString();

            FailedLoginsText.Text = loadedLogs.Count(log =>
                string.Equals(
                    log.Status,
                    "Failed",
                    StringComparison.OrdinalIgnoreCase)).ToString();
        }

        // UPDATE DASHBOARD COUNTERS AND CHARTS
        private void UpdateDashboard()
        {
            LogData();

            AlertsText.Text = detectedAlerts.Count.ToString();

            HighAlertsText.Text = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.Severity,
                    "High",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            MediumAlertsText.Text = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.Severity,
                    "Medium",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            ResolvedAlertsText.Text = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.InvestigationStatus,
                    "Resolved",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            NewAlertsText.Text = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.InvestigationStatus,
                    "New",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            InvestigatingAlertsText.Text = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.InvestigationStatus,
                    "Investigating",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            ActiveAlertsText.Text = detectedAlerts.Count(alert =>
                !string.Equals(
                    alert.InvestigationStatus,
                    "Resolved",
                    StringComparison.OrdinalIgnoreCase)).ToString();

            UpdatePriorityQueue();
            UpdateAnalyticsCharts();
        }

        // POPULATE THE UNRESOLVED HIGH-SEVERITY PRIORITY QUEUE
        private void UpdatePriorityQueue()
        {
            List<SecurityAlert> priorityAlerts = detectedAlerts
                .Where(alert =>
                    string.Equals(
                        alert.Severity,
                        "High",
                        StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(
                        alert.InvestigationStatus,
                        "Resolved",
                        StringComparison.OrdinalIgnoreCase))
                .OrderBy(alert => GetSeverityRank(alert.Severity))
                .ThenByDescending(alert => alert.Timestamp)
                .ToList();

            PriorityAlertsDataGrid.ItemsSource = priorityAlerts;
        }

        // UPDATE ALL THREE ANALYTICS CHARTS
        private void UpdateAnalyticsCharts()
        {
            UpdateLoginActivityChart();
            UpdateSeverityChart();
            UpdateTopIpChart();
        }

        // CHART 1: FAILED LOGINS OVER TIME
        private void UpdateLoginActivityChart()
        {
            var hourlyActivity = loadedLogs
                .Where(log => string.Equals(
                    log.Status,
                    "Failed",
                    StringComparison.OrdinalIgnoreCase))
                .GroupBy(log => new DateTime(
                    log.Timestamp.Year,
                    log.Timestamp.Month,
                    log.Timestamp.Day,
                    log.Timestamp.Hour,
                    0,
                    0))
                .OrderBy(group => group.Key)
                .ToList();

            string[] labels = hourlyActivity
                .Select(group => group.Key.ToString("MM-dd HH:mm"))
                .ToArray();

            int[] counts = hourlyActivity
                .Select(group => group.Count())
                .ToArray();

            LoginActivityChart.Series = new ISeries[]
            {
                new LineSeries<int>
                {
                    Name = "Failed logins",
                    Values = counts,
                    Fill = null,
                    GeometrySize = 8,
                    Stroke = new SolidColorPaint(SKColors.DodgerBlue)
                    {
                        StrokeThickness = 3
                    },
                    GeometryStroke = new SolidColorPaint(SKColors.DodgerBlue)
                    {
                        StrokeThickness = 3
                    }
                }
            };

            LoginActivityChart.XAxes = new Axis[]
            {
                new Axis
                {
                    Labels = labels,
                    LabelsRotation = 25
                }
            };

            LoginActivityChart.YAxes = new Axis[]
            {
                new Axis
                {
                    Name = "Failed logins",
                    MinLimit = 0
                }
            };
        }

        // CHART 2: ALERT SEVERITY DISTRIBUTION
        private void UpdateSeverityChart()
        {
            int highCount = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.Severity,
                    "High",
                    StringComparison.OrdinalIgnoreCase));

            int mediumCount = detectedAlerts.Count(alert =>
                string.Equals(
                    alert.Severity,
                    "Medium",
                    StringComparison.OrdinalIgnoreCase));

            int otherCount = detectedAlerts.Count(alert =>
                !string.Equals(
                    alert.Severity,
                    "High",
                    StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(
                    alert.Severity,
                    "Medium",
                    StringComparison.OrdinalIgnoreCase));

            SeverityChart.Series = new ISeries[]
            {
                new PieSeries<int>
                {
                    Name = "High",
                    Values = new[] { highCount },
                    Fill = new SolidColorPaint(SKColors.IndianRed)
                },
                new PieSeries<int>
                {
                    Name = "Medium",
                    Values = new[] { mediumCount },
                    Fill = new SolidColorPaint(SKColors.Orange)
                },
                new PieSeries<int>
                {
                    Name = "Other",
                    Values = new[] { otherCount },
                    Fill = new SolidColorPaint(SKColors.SteelBlue)
                }
            };
        }

        // CHART 3: TOP FIVE IP ADDRESSES BY ALERT COUNT
        private void UpdateTopIpChart()
        {
            var topAddresses = detectedAlerts
                .GroupBy(alert =>
                    string.IsNullOrWhiteSpace(alert.IPAddress)
                        ? "Unknown IP"
                        : alert.IPAddress)
                .Select(group => new
                {
                    IPAddress = group.Key,
                    Count = group.Count()
                })
                .OrderByDescending(item => item.Count)
                .ThenBy(item => item.IPAddress)
                .Take(5)
                .ToList();

            string[] labels = topAddresses
                .Select(item => item.IPAddress)
                .ToArray();

            int[] counts = topAddresses
                .Select(item => item.Count)
                .ToArray();

            TopIpChart.Series = new ISeries[]
            {
                new ColumnSeries<int>
                {
                    Name = "Detected alerts",
                    Values = counts,
                    Fill = new SolidColorPaint(SKColors.MediumPurple)
                }
            };

            TopIpChart.XAxes = new Axis[]
            {
                new Axis
                {
                    Labels = labels,
                    LabelsRotation = 15
                }
            };

            TopIpChart.YAxes = new Axis[]
            {
                new Axis
                {
                    Name = "Alert count",
                    MinLimit = 0
                }
            };
        }

        // CLEAR WORKSPACE
        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            loadedLogs.Clear();
            detectedAlerts.Clear();
            hasAnalyzedLogs = false;

            AlertDataGrid.ItemsSource = null;
            PriorityAlertsDataGrid.ItemsSource = null;
            LogDataGrid.ItemsSource = null;

            LogSearchTextBox.Clear();
            StatusFilterComboBox.SelectedIndex = 0;

            ResetAlertFilterControls();

            UpdateDashboard();
            UpdateSystemStatus();

            StatusText.Text = "Ready. Import a security log file.";
        }

        // OPEN SELECTED ALERT FROM THE MAIN ALERT TABLE
        private void ViewDetailsButton_Click(object sender, RoutedEventArgs e)
        {
            SecurityAlert selectedAlert =
                AlertDataGrid.SelectedItem as SecurityAlert;

            if (selectedAlert == null)
            {
                MessageBox.Show(
                    "Please select a security alert first.",
                    "No Alert Selected",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            OpenAlertInvestigation(selectedAlert);
        }

        // OPEN SELECTED ALERT FROM THE PRIORITY QUEUE
        private void OpenPriorityAlertButton_Click(
            object sender, RoutedEventArgs e)
        {
            SecurityAlert selectedAlert =
                PriorityAlertsDataGrid.SelectedItem as SecurityAlert;

            if (selectedAlert == null)
            {
                MessageBox.Show(
                    "Please select a High-severity alert from the priority queue first.",
                    "No Priority Alert Selected",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            OpenAlertInvestigation(selectedAlert);
        }

        // SHARED INVESTIGATION WORKFLOW
        private void OpenAlertInvestigation(SecurityAlert selectedAlert)
        {
            AlertDetailsWindow detailsWindow =
                new AlertDetailsWindow(selectedAlert, loadedLogs);

            detailsWindow.Owner = this;

            if (detailsWindow.ShowDialog() != true)
                return;

            try
            {
                Dictionary<string, InvestigationRecord> savedInvestigations =
                    investigationStorage.LoadInvestigations();

                string key = GetAlertKey(selectedAlert);

                savedInvestigations[key] = new InvestigationRecord
                {
                    Status = selectedAlert.InvestigationStatus ?? "New",
                    Notes = selectedAlert.InvestigationNotes ?? "",
                    AssignedAnalyst = selectedAlert.AssignedAnalyst ?? "",
                    InvestigationStartedAt =
                        selectedAlert.InvestigationStartedAt,
                    ResolvedAt = selectedAlert.ResolvedAt,
                    History = selectedAlert.InvestigationHistory
                        ?? new List<InvestigationHistoryEntry>()
                };

                investigationStorage.SaveInvestigations(savedInvestigations);

                RefreshAlertList();
                UpdateDashboard();
                UpdateSystemStatus();

                StatusText.Text =
                    $"Investigation saved: {selectedAlert.InvestigationStatus}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"The investigation could not be saved.\n\n{ex.Message}",
                    "Storage Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // EXPORT SECURITY ALERT REPORT, INCLUDING SUPPORTING EVIDENCE
        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            if (detectedAlerts.Count == 0)
            {
                MessageBox.Show(
                    "There are no security alerts to export.",
                    "No Alerts",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            SaveFileDialog dialog = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt",
                FileName = "SOC_Alert_Report.txt",
                Title = "Export SOC Security Alert Report"
            };

            if (dialog.ShowDialog() != true)
                return;

            try
            {
                StringBuilder report = new StringBuilder();

                report.AppendLine("SOC LOG ANALYZER - SECURITY ALERT REPORT");
                report.AppendLine("========================================");
                report.AppendLine(
                    $"Report Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                report.AppendLine($"Total Alerts: {detectedAlerts.Count}");
                report.AppendLine();

                foreach (SecurityAlert alert in detectedAlerts)
                {
                    report.AppendLine("SECURITY ALERT");
                    report.AppendLine("----------------------------------------");

                    report.AppendLine(
                        $"Timestamp: {alert.Timestamp:yyyy-MM-dd HH:mm:ss}");

                    report.AppendLine($"Severity: {alert.Severity}");

                    report.AppendLine(
                        $"Detection Rule: {ValueOrFallback(alert.DetectionRule, "Not specified")}");

                    report.AppendLine(
                        $"Investigation Status: {ValueOrFallback(alert.InvestigationStatus, "New")}");

                    report.AppendLine(
                        "Assigned Analyst: " +
                        ValueOrFallback(alert.AssignedAnalyst, "Unassigned"));

                    report.AppendLine(
                        "Investigation Started: " +
                        (alert.InvestigationStartedAt.HasValue
                            ? alert.InvestigationStartedAt.Value.ToString(
                                "yyyy-MM-dd HH:mm:ss")
                            : "Not started"));

                    report.AppendLine(
                        "Resolved At: " +
                        (alert.ResolvedAt.HasValue
                            ? alert.ResolvedAt.Value.ToString(
                                "yyyy-MM-dd HH:mm:ss")
                            : "Not resolved"));

                    report.AppendLine(
                        $"Username: {ValueOrFallback(alert.Username, "Unknown")}");

                    report.AppendLine(
                        $"Source IP: {ValueOrFallback(alert.IPAddress, "Unknown")}");

                    report.AppendLine($"Failed Attempts: {alert.FailedAttempts}");

                    report.AppendLine(
                        $"Description: {ValueOrFallback(alert.Description, "No description available")}");

                    report.AppendLine();
                    report.AppendLine("SUPPORTING EVIDENCE LOGS");
                    report.AppendLine("----------------------------------------");

                    List<LogEntry> evidenceLogs = alert.EvidenceLogs
                        ?? new List<LogEntry>();

                    if (evidenceLogs.Count == 0)
                    {
                        report.AppendLine(
                            "No evidence logs were attached to this alert.");
                    }
                    else
                    {
                        report.AppendLine(
                            $"Evidence event count: {evidenceLogs.Count}");
                        report.AppendLine();

                        foreach (LogEntry log in evidenceLogs
                                     .Where(log => log != null)
                                     .OrderBy(log => log.Timestamp))
                        {
                            report.AppendLine(
                                $"Timestamp: {log.Timestamp:yyyy-MM-dd HH:mm:ss}");

                            report.AppendLine(
                                $"Username: {ValueOrFallback(log.Username, "Unknown")}");

                            report.AppendLine(
                                $"Source IP: {ValueOrFallback(log.IPAddress, "Unknown")}");

                            report.AppendLine(
                                $"Status: {ValueOrFallback(log.Status, "Unknown")}");

                            report.AppendLine(
                                $"Event Type: {ValueOrFallback(log.EventType, "Unknown")}");

                            report.AppendLine();
                        }
                    }

                    report.AppendLine("INVESTIGATION NOTES");
                    report.AppendLine("----------------------------------------");
                    report.AppendLine(
                        ValueOrFallback(
                            alert.InvestigationNotes,
                            "No notes recorded."));

                    report.AppendLine();
                    report.AppendLine("INVESTIGATION HISTORY");
                    report.AppendLine("----------------------------------------");

                    if (alert.InvestigationHistory == null ||
                        alert.InvestigationHistory.Count == 0)
                    {
                        report.AppendLine("No history recorded.");
                    }
                    else
                    {
                        foreach (InvestigationHistoryEntry entry
                                 in alert.InvestigationHistory)
                        {
                            report.AppendLine(
                                $"Changed At: {entry.ChangedAt:yyyy-MM-dd HH:mm:ss}");

                            report.AppendLine(
                                $"Analyst: {ValueOrFallback(entry.Analyst, "Unassigned")}");

                            report.AppendLine(
                                $"Action: {ValueOrFallback(entry.Action, "No action recorded")}");

                            report.AppendLine(
                                $"Previous Status: {ValueOrFallback(entry.PreviousStatus, "Unknown")}");

                            report.AppendLine(
                                $"New Status: {ValueOrFallback(entry.NewStatus, "Unknown")}");

                            report.AppendLine(
                                $"Notes: {ValueOrFallback(entry.Notes, "No notes")}");

                            report.AppendLine();
                        }
                    }

                    report.AppendLine();
                    report.AppendLine("========================================");
                    report.AppendLine();
                }

                File.WriteAllText(dialog.FileName, report.ToString());

                MessageBox.Show(
                    $"Security alert report exported successfully.\n\nSaved to:\n{dialog.FileName}",
                    "Export Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                StatusText.Text =
                    "Security alert report exported successfully.";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"The report could not be exported.\n\n{ex.Message}",
                    "Export Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // PROVIDE A SAFE FALLBACK FOR EMPTY REPORT VALUES
        private string ValueOrFallback(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value)
                ? fallback
                : value.Trim();
        }
    }
}
