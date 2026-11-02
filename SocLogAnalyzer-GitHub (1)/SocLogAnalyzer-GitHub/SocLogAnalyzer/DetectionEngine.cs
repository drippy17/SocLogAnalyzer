
using System;
using System.Collections.Generic;
using System.Linq;

namespace SocLogAnalyzer
{
    public class DetectionEngine
    {
        private const int MediumThreshold = 5;
        private const int HighThreshold = 10;
        private const int TimeWindowMinutes = 5;

        private const int MediumSprayThreshold = 5;
        private const int HighSprayThreshold = 10;

        public List<SecurityAlert> Analyze(List<LogEntry> logs)
        {
            List<SecurityAlert> alerts = new List<SecurityAlert>();

            if (logs == null || logs.Count == 0)
                return alerts;

            List<LogEntry> validLogs = logs
                .Where(log => log != null)
                .OrderBy(log => log.Timestamp)
                .ToList();

            List<LogEntry> failedLogins = validLogs
                .Where(log => IsStatus(log, "Failed"))
                .ToList();

            List<LogEntry> successfulLogins = validLogs
                .Where(log => IsStatus(log, "Success"))
                .ToList();

            // RULE 1: Repeated failed logins for the same username and IP.
            var groupedLogins = failedLogins
                .GroupBy(log => new
                {
                    Username = (log.Username ?? "").Trim(),
                    IPAddress = (log.IPAddress ?? "").Trim()
                });

            foreach (var group in groupedLogins)
            {
                List<LogEntry> attempts = group
                    .OrderBy(log => log.Timestamp)
                    .ToList();

                int i = 0;

                while (i < attempts.Count)
                {
                    DateTime windowStart = attempts[i].Timestamp;
                    DateTime windowEnd =
                        windowStart.AddMinutes(TimeWindowMinutes);

                    List<LogEntry> windowAttempts = attempts
                        .Where(log =>
                            log.Timestamp >= windowStart &&
                            log.Timestamp <= windowEnd)
                        .ToList();

                    if (windowAttempts.Count >= MediumThreshold)
                    {
                        int count = windowAttempts.Count;

                        alerts.Add(new SecurityAlert
                        {
                            Timestamp = windowStart,
                            Username = group.Key.Username,
                            IPAddress = group.Key.IPAddress,
                            FailedAttempts = count,
                            Severity = count >= HighThreshold
                                ? "High" : "Medium",
                            DetectionRule = "Repeated Failed Logins",
                            Description =
                                $"Detection rule: Repeated Failed Logins. " +
                                $"{count} failed login attempts for " +
                                $"'{group.Key.Username}' from IP " +
                                $"{group.Key.IPAddress} within " +
                                $"{TimeWindowMinutes} minutes.",
                            EvidenceLogs = new List<LogEntry>(windowAttempts)
                        });

                        while (i < attempts.Count &&
                               attempts[i].Timestamp <= windowEnd)
                            i++;
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            // RULE 2: Possible password spraying from one IP.
            var groupedByIp = failedLogins
                .GroupBy(log => (log.IPAddress ?? "").Trim());

            foreach (var ipGroup in groupedByIp)
            {
                List<LogEntry> attempts = ipGroup
                    .OrderBy(log => log.Timestamp)
                    .ToList();

                int i = 0;

                while (i < attempts.Count)
                {
                    DateTime windowStart = attempts[i].Timestamp;
                    DateTime windowEnd =
                        windowStart.AddMinutes(TimeWindowMinutes);

                    List<LogEntry> windowAttempts = attempts
                        .Where(log =>
                            log.Timestamp >= windowStart &&
                            log.Timestamp <= windowEnd)
                        .ToList();

                    int distinctUsernames = windowAttempts
                        .Select(log => (log.Username ?? "").Trim())
                        .Where(username =>
                            !string.IsNullOrWhiteSpace(username))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Count();

                    if (distinctUsernames >= MediumSprayThreshold)
                    {
                        alerts.Add(new SecurityAlert
                        {
                            Timestamp = windowStart,
                            Username = "Multiple users",
                            IPAddress = ipGroup.Key,
                            FailedAttempts = windowAttempts.Count,
                            Severity = distinctUsernames >= HighSprayThreshold
                                ? "High" : "Medium",
                            DetectionRule = "Possible Password Spraying",
                            Description =
                                $"Detection rule: Possible Password Spraying. " +
                                $"{windowAttempts.Count} failed attempts " +
                                $"against {distinctUsernames} distinct " +
                                $"usernames from IP {ipGroup.Key} within " +
                                $"{TimeWindowMinutes} minutes.",
                            EvidenceLogs = new List<LogEntry>(windowAttempts)
                        });

                        while (i < attempts.Count &&
                               attempts[i].Timestamp <= windowEnd)
                            i++;
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            // RULE 3: Repeated failures followed by a successful login.
            foreach (LogEntry success in successfulLogins)
            {
                string username = (success.Username ?? "").Trim();
                string ipAddress = (success.IPAddress ?? "").Trim();

                if (string.IsNullOrWhiteSpace(username) ||
                    string.IsNullOrWhiteSpace(ipAddress))
                    continue;

                DateTime windowStart =
                    success.Timestamp.AddMinutes(-TimeWindowMinutes);

                List<LogEntry> precedingFailures = failedLogins
                    .Where(log =>
                        string.Equals(
                            (log.Username ?? "").Trim(),
                            username,
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(
                            (log.IPAddress ?? "").Trim(),
                            ipAddress,
                            StringComparison.OrdinalIgnoreCase) &&
                        log.Timestamp >= windowStart &&
                        log.Timestamp < success.Timestamp)
                    .ToList();

                if (precedingFailures.Count < MediumThreshold)
                    continue;

                List<LogEntry> evidence =
                    new List<LogEntry>(precedingFailures);

                // Include the successful login as evidence.
                evidence.Add(success);

                alerts.Add(new SecurityAlert
                {
                    Timestamp = success.Timestamp,
                    Username = username,
                    IPAddress = ipAddress,
                    FailedAttempts = precedingFailures.Count,
                    Severity = "High",
                    DetectionRule = "Possible Account Compromise",
                    Description =
                        "Detection rule: Possible Account Compromise. " +
                        $"{precedingFailures.Count} failed login attempts " +
                        $"were followed by a successful login for " +
                        $"'{username}' from IP {ipAddress} within " +
                        $"{TimeWindowMinutes} minutes. Verify whether " +
                        "the successful login was legitimate.",
                    EvidenceLogs = evidence
                });
            }

            return alerts
                .OrderByDescending(alert =>
                    string.Equals(
                        alert.Severity,
                        "High",
                        StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(alert => alert.Timestamp)
                .ToList();
        }

        private static bool IsStatus(
            LogEntry log,
            string expectedStatus)
        {
            return string.Equals(
                (log.Status ?? "").Trim(),
                expectedStatus,
                StringComparison.OrdinalIgnoreCase);
        }
    }
}
