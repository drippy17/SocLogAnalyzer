using System;
using System.Collections.Generic;
using System.IO;

namespace SocLogAnalyzer
{
    public class LogParser
    {
        public List<LogEntry> ParseLogFile(string filePath)
        {
            List<LogEntry> entries = new List<LogEntry>();

            string[] lines = File.ReadAllLines(filePath);

            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                string[] parts = line.Split(',');

                if (parts.Length < 5)
                    continue;

                DateTime timestamp;

                if (!DateTime.TryParse(parts[0], out timestamp))
                    continue;

                LogEntry entry = new LogEntry
                {
                    Timestamp = timestamp,
                    Username = parts[1].Trim(),
                    IPAddress = parts[2].Trim(),
                    Status = parts[3].Trim(),
                    EventType = parts[4].Trim()
                };

                entries.Add(entry);
            }

            return entries;
        }
    }
}