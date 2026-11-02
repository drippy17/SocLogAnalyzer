
using System;
using System.Collections.Generic;

namespace SocLogAnalyzer
{
    public class SecurityAlert
    {
        public DateTime Timestamp { get; set; }

        public string Username { get; set; } = "";

        public string IPAddress { get; set; } = "";

        public int FailedAttempts { get; set; }

        public string Severity { get; set; } = "";

        public string Description { get; set; } = "";

        // Evidence log entries that support this alert.
        public List<LogEntry> EvidenceLogs { get; set; }
            = new List<LogEntry>();

        // Name of the rule that generated this alert.
        public string DetectionRule { get; set; } = "";

        public string InvestigationStatus { get; set; } = "New";

        public string InvestigationNotes { get; set; } = "";

        public string AssignedAnalyst { get; set; } = "";

        public DateTime? InvestigationStartedAt { get; set; }

        public DateTime? ResolvedAt { get; set; }

        public List<InvestigationHistoryEntry> InvestigationHistory
        {
            get;
            set;
        } = new List<InvestigationHistoryEntry>();
    }
}
