using System;

namespace SocLogAnalyzer
{
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }

        public string Username { get; set; }

        public string IPAddress { get; set; }

        public string Status { get; set; }

        public string EventType { get; set; }

        public LogEntry()
        {
            Username = "";
            IPAddress = "";
            Status = "";
            EventType = "";
        }
    }
}