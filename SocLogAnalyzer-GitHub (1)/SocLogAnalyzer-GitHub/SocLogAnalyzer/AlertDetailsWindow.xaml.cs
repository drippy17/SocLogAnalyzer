
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SocLogAnalyzer
{
    public partial class AlertDetailsWindow : Window
    {
        private readonly SecurityAlert currentAlert;
        private readonly List<LogEntry> availableLogs;

        private readonly string originalStatus;
        private readonly string originalAnalyst;
        private readonly string originalNotes;

        public AlertDetailsWindow(
            SecurityAlert selectedAlert,
            List<LogEntry> logs)
        {
            InitializeComponent();

            currentAlert = selectedAlert ??
                throw new ArgumentNullException(nameof(selectedAlert));

            availableLogs = logs ?? new List<LogEntry>();

            originalStatus = selectedAlert.InvestigationStatus ?? "New";
            originalAnalyst = selectedAlert.AssignedAnalyst ?? "";
            originalNotes = selectedAlert.InvestigationNotes ?? "";

            InvestigationStatusComboBox.SelectedIndex =
                string.Equals(originalStatus, "Investigating",
                    StringComparison.OrdinalIgnoreCase) ? 1 :
                string.Equals(originalStatus, "Resolved",
                    StringComparison.OrdinalIgnoreCase) ? 2 : 0;

            SeverityText.Text = selectedAlert.Severity ?? "";
            UsernameText.Text = selectedAlert.Username ?? "";
            IPAddressText.Text = selectedAlert.IPAddress ?? "";

            FailedAttemptsText.Text =
                selectedAlert.FailedAttempts.ToString();

            TimestampText.Text =
                selectedAlert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");

            DescriptionText.Text = selectedAlert.Description ?? "";

            AssignedAnalystTextBox.Text = originalAnalyst;
            InvestigationNotesTextBox.Text = originalNotes;

            InvestigationStartedText.Text =
                selectedAlert.InvestigationStartedAt.HasValue
                    ? selectedAlert.InvestigationStartedAt.Value.ToString(
                        "yyyy-MM-dd HH:mm:ss")
                    : "Not started";

            ResolvedAtText.Text =
                selectedAlert.ResolvedAt.HasValue
                    ? selectedAlert.ResolvedAt.Value.ToString(
                        "yyyy-MM-dd HH:mm:ss")
                    : "Not resolved";

            if (string.Equals(
                selectedAlert.Severity,
                "High",
                StringComparison.OrdinalIgnoreCase))
            {
                SeverityText.Foreground =
                    new SolidColorBrush(Color.FromRgb(252, 165, 165));
            }
            else
            {
                SeverityText.Foreground =
                    new SolidColorBrush(Color.FromRgb(252, 211, 77));
            }

            SetDetectionInformation(selectedAlert);
            LoadRelatedEvidence(selectedAlert);

            currentAlert.InvestigationHistory ??=
                new List<InvestigationHistoryEntry>();

            InvestigationHistoryDataGrid.ItemsSource =
                currentAlert.InvestigationHistory;

            UpdateHistoryVisibility();
        }

        private void SetDetectionInformation(SecurityAlert alert)
        {
            string rule = alert.DetectionRule ?? "";

            bool isPasswordSpraying =
                rule.Contains(
                    "Password Spraying",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    alert.Username,
                    "Multiple users",
                    StringComparison.OrdinalIgnoreCase) ||
                (alert.Description ?? "").Contains(
                    "password spraying",
                    StringComparison.OrdinalIgnoreCase);

            bool isAccountCompromise =
                rule.Contains(
                    "Account Compromise",
                    StringComparison.OrdinalIgnoreCase) ||
                (alert.Description ?? "").Contains(
                    "successful login",
                    StringComparison.OrdinalIgnoreCase) &&
                (alert.Description ?? "").Contains(
                    "failed",
                    StringComparison.OrdinalIgnoreCase);

            if (isAccountCompromise)
            {
                DetectionRuleText.Text =
                    "Possible Account Compromise";

                RecommendedActionText.Text =
                    "1. Review the failed login attempts and the subsequent " +
                    "successful login.\n\n" +
                    "2. Confirm whether the successful login was expected " +
                    "and authorised by the account owner.\n\n" +
                    "3. Review the source IP, timestamps and any additional " +
                    "available authentication logs.\n\n" +
                    "4. If the activity appears unauthorised, follow your " +
                    "organisation's incident-response process.";
            }
            else if (isPasswordSpraying)
            {
                DetectionRuleText.Text =
                    "Possible Password Spraying";

                RecommendedActionText.Text =
                    "1. Review the source IP and the usernames targeted.\n\n" +
                    "2. Check whether the source is an approved scanner, " +
                    "VPN gateway or other known system.\n\n" +
                    "3. Correlate the events with successful logins and " +
                    "other security logs, if available.\n\n" +
                    "4. If the activity is unauthorised, follow your " +
                    "organisation's incident-response process.";
            }
            else
            {
                DetectionRuleText.Text =
                    string.IsNullOrWhiteSpace(rule)
                        ? "Repeated Failed Login Attempts"
                        : rule;

                RecommendedActionText.Text =
                    "1. Review the failed attempts and confirm the " +
                    "username and source IP.\n\n" +
                    "2. Check for successful logins from the same IP " +
                    "before and after the alert.\n\n" +
                    "3. Determine whether the activity matches expected " +
                    "user behaviour or an authorised security test.\n\n" +
                    "4. If the activity appears unauthorised, follow your " +
                    "organisation's incident-response process.";
            }
        }

        private void LoadRelatedEvidence(SecurityAlert alert)
        {
            // Prefer the evidence collected by the detection engine.
            List<LogEntry> evidenceLogs =
                alert.EvidenceLogs ?? new List<LogEntry>();

            List<LogEntry> relatedEvents;

            if (evidenceLogs.Count > 0)
            {
                relatedEvents = evidenceLogs
                    .Where(log => log != null)
                    .OrderBy(log => log.Timestamp)
                    .ToList();

                EvidenceSummaryText.Text =
                    $"Showing {relatedEvents.Count} evidence event(s) " +
                    "collected by the detection engine for this alert. " +
                    "Review these events alongside the alert description; " +
                    "they are supporting evidence, not proof by themselves " +
                    "that an attack occurred.";
            }
            else
            {
                // Fallback for older alerts that do not contain saved evidence.
                DateTime start = alert.Timestamp.AddMinutes(-5);
                DateTime end = alert.Timestamp.AddMinutes(5);

                bool isPasswordSpraying =
                    string.Equals(
                        alert.Username,
                        "Multiple users",
                        StringComparison.OrdinalIgnoreCase) ||
                    (alert.DetectionRule ?? "").Contains(
                        "Password Spraying",
                        StringComparison.OrdinalIgnoreCase);

                relatedEvents = availableLogs
                    .Where(log =>
                        log != null &&
                        log.Timestamp >= start &&
                        log.Timestamp <= end &&
                        string.Equals(
                            (log.IPAddress ?? "").Trim(),
                            (alert.IPAddress ?? "").Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    .Where(log =>
                        isPasswordSpraying ||
                        string.Equals(
                            (log.Username ?? "").Trim(),
                            (alert.Username ?? "").Trim(),
                            StringComparison.OrdinalIgnoreCase))
                    .OrderBy(log => log.Timestamp)
                    .ToList();

                if (relatedEvents.Count == 0)
                {
                    EvidenceSummaryText.Text =
                        "No saved evidence was attached to this alert, " +
                        "and no related log events were found within five " +
                        "minutes before or after the alert timestamp.";
                }
                else
                {
                    EvidenceSummaryText.Text =
                        $"No saved evidence was attached to this alert. " +
                        $"Showing {relatedEvents.Count} related log event(s) " +
                        "from the five-minute period before or after the " +
                        "alert timestamp. These are contextual events and " +
                        "may not all be part of the original detection.";
                }
            }

            EvidenceDataGrid.ItemsSource = relatedEvents;
        }

        private void UpdateHistoryVisibility()
        {
            bool hasHistory =
                currentAlert.InvestigationHistory != null &&
                currentAlert.InvestigationHistory.Count > 0;

            HistoryEmptyText.Visibility =
                hasHistory ? Visibility.Collapsed : Visibility.Visible;

            InvestigationHistoryDataGrid.Visibility =
                hasHistory ? Visibility.Visible : Visibility.Collapsed;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            if (!(InvestigationStatusComboBox.SelectedItem
                  is ComboBoxItem item))
            {
                MessageBox.Show(
                    "Please select an investigation status.",
                    "Missing Status",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            string newStatus = item.Content?.ToString() ?? "New";
            string newAnalyst = AssignedAnalystTextBox.Text.Trim();
            string newNotes = InvestigationNotesTextBox.Text.Trim();

            DateTime now = DateTime.Now;

            bool statusChanged =
                !string.Equals(originalStatus, newStatus,
                    StringComparison.OrdinalIgnoreCase);

            bool analystChanged =
                !string.Equals(originalAnalyst, newAnalyst,
                    StringComparison.Ordinal);

            bool notesChanged =
                !string.Equals(originalNotes, newNotes,
                    StringComparison.Ordinal);

            if (newStatus == "Investigating" &&
                !currentAlert.InvestigationStartedAt.HasValue)
            {
                currentAlert.InvestigationStartedAt = now;
                InvestigationStartedText.Text =
                    now.ToString("yyyy-MM-dd HH:mm:ss");
            }

            if (newStatus == "Resolved")
            {
                if (!string.Equals(
                        originalStatus,
                        "Resolved",
                        StringComparison.OrdinalIgnoreCase) ||
                    !currentAlert.ResolvedAt.HasValue)
                {
                    currentAlert.ResolvedAt = now;
                }

                ResolvedAtText.Text =
                    currentAlert.ResolvedAt.Value.ToString(
                        "yyyy-MM-dd HH:mm:ss");
            }
            else
            {
                currentAlert.ResolvedAt = null;
                ResolvedAtText.Text = "Not resolved";
            }

            if (statusChanged || analystChanged || notesChanged)
            {
                string action;

                if (statusChanged)
                {
                    action =
                        $"Status changed from {originalStatus} to {newStatus}";
                }
                else if (analystChanged)
                {
                    action = "Assigned analyst updated";
                }
                else
                {
                    action = "Investigation notes updated";
                }

                currentAlert.InvestigationHistory ??=
                    new List<InvestigationHistoryEntry>();

                currentAlert.InvestigationHistory.Add(
                    new InvestigationHistoryEntry
                    {
                        ChangedAt = now,
                        Analyst = newAnalyst,
                        Action = action,
                        PreviousStatus = originalStatus,
                        NewStatus = newStatus,
                        Notes = newNotes
                    });
            }

            currentAlert.InvestigationStatus = newStatus;
            currentAlert.AssignedAnalyst = newAnalyst;
            currentAlert.InvestigationNotes = newNotes;

            InvestigationHistoryDataGrid.Items.Refresh();
            UpdateHistoryVisibility();

            DialogResult = true;
            Close();
        }
    }
}
