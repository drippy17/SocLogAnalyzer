
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace SocLogAnalyzer
{
    public class InvestigationHistoryEntry
    {
        public DateTime ChangedAt { get; set; } = DateTime.Now;

        public string Analyst { get; set; } = "";

        public string Action { get; set; } = "";

        public string PreviousStatus { get; set; } = "";

        public string NewStatus { get; set; } = "";

        public string Notes { get; set; } = "";
    }

    public class InvestigationRecord
    {
        public string Status { get; set; } = "New";

        public string Notes { get; set; } = "";

        public string AssignedAnalyst { get; set; } = "";

        public DateTime? InvestigationStartedAt { get; set; }

        public DateTime? ResolvedAt { get; set; }

        public List<InvestigationHistoryEntry> History { get; set; }
            = new List<InvestigationHistoryEntry>();
    }

    public class InvestigationStorage
    {
        private readonly string filePath =
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "SocLogAnalyzer",
                "investigations.json");

        public Dictionary<string, InvestigationRecord>
            LoadInvestigations()
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return new Dictionary<string, InvestigationRecord>();
                }

                string json = File.ReadAllText(filePath);

                return JsonSerializer.Deserialize<
                    Dictionary<string, InvestigationRecord>>(json)
                    ?? new Dictionary<string, InvestigationRecord>();
            }
            catch (JsonException)
            {
                return new Dictionary<string, InvestigationRecord>();
            }
            catch (IOException)
            {
                return new Dictionary<string, InvestigationRecord>();
            }
        }

        public void SaveInvestigations(
            Dictionary<string, InvestigationRecord> investigations)
        {
            string? directory = Path.GetDirectoryName(filePath);

            if (directory != null)
            {
                Directory.CreateDirectory(directory);
            }

            string json = JsonSerializer.Serialize(
                investigations,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                });

            File.WriteAllText(filePath, json);
        }
    }
}
