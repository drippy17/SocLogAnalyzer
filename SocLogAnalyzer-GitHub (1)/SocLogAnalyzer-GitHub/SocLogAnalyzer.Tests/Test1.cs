
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SocLogAnalyzer.Tests
{
    [TestClass]
    public class DetectionEngineTests
    {
        private readonly DetectionEngine detectionEngine =
            new DetectionEngine();

        // TEST 1: Five failed logins should generate a Medium alert.
        [TestMethod]
        public void RepeatedFailedLogins_FiveAttempts_DetectsMediumAlert()
        {
            DateTime start = new DateTime(2026, 1, 1, 10, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 5)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 30),
                    Username = "testuser",
                    IPAddress = "192.168.1.10",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsTrue(alerts.Any(a =>
                a.DetectionRule == "Repeated Failed Logins" &&
                a.Severity == "Medium"));
        }

        // TEST 2: Ten failed logins should generate a High alert.
        [TestMethod]
        public void RepeatedFailedLogins_TenAttempts_DetectsHighAlert()
        {
            DateTime start = new DateTime(2026, 1, 1, 10, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 10)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 20),
                    Username = "testuser",
                    IPAddress = "192.168.1.10",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsTrue(alerts.Any(a =>
                a.DetectionRule == "Repeated Failed Logins" &&
                a.Severity == "High"));
        }

        // TEST 3: Five distinct usernames should trigger password spraying.
        [TestMethod]
        public void PasswordSpraying_FiveDistinctUsers_DetectsMediumAlert()
        {
            DateTime start = new DateTime(2026, 1, 1, 11, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 5)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 30),
                    Username = "user" + i,
                    IPAddress = "192.168.1.20",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsTrue(alerts.Any(a =>
                a.DetectionRule == "Possible Password Spraying" &&
                a.Severity == "Medium"));
        }

        // TEST 4: Failed logins followed by success should trigger a High alert.
        [TestMethod]
        public void FailedLoginsFollowedBySuccess_DetectsPossibleAccountCompromise()
        {
            DateTime start = new DateTime(2026, 1, 1, 12, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 5)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 30),
                    Username = "testuser",
                    IPAddress = "192.168.1.30",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            logs.Add(new LogEntry
            {
                Timestamp = start.AddMinutes(3),
                Username = "testuser",
                IPAddress = "192.168.1.30",
                Status = "Success",
                EventType = "Login"
            });

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsTrue(alerts.Any(a =>
                a.DetectionRule == "Possible Account Compromise" &&
                a.Severity == "High"));
        }

        // TEST 5: A normal successful login should generate no alerts.
        [TestMethod]
        public void SuccessfulLoginOnly_DoesNotGenerateAlerts()
        {
            List<LogEntry> logs = new List<LogEntry>
            {
                new LogEntry
                {
                    Timestamp = new DateTime(2026, 1, 1, 13, 0, 0),
                    Username = "normaluser",
                    IPAddress = "192.168.1.40",
                    Status = "Success",
                    EventType = "Login"
                }
            };

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.AreEqual(0, alerts.Count);
        }

        // TEST 6: Four failed attempts should not trigger the repeated-login rule.
        [TestMethod]
        public void RepeatedFailedLogins_FourAttempts_DoesNotTriggerRule()
        {
            DateTime start = new DateTime(2026, 1, 1, 14, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 4)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 30),
                    Username = "testuser",
                    IPAddress = "192.168.1.50",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsFalse(alerts.Any(a =>
                a.DetectionRule == "Repeated Failed Logins"));
        }

        // TEST 7: Ten distinct usernames should trigger a High spraying alert.
        [TestMethod]
        public void PasswordSpraying_TenDistinctUsers_DetectsHighAlert()
        {
            DateTime start = new DateTime(2026, 1, 1, 15, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 10)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddSeconds(i * 20),
                    Username = "user" + i,
                    IPAddress = "192.168.1.60",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsTrue(alerts.Any(a =>
                a.DetectionRule == "Possible Password Spraying" &&
                a.Severity == "High"));
        }

        // TEST 8: Attempts six minutes apart should not combine into one alert.
        [TestMethod]
        public void RepeatedFailedLogins_OutsideFiveMinuteWindow_DoesNotCombineAttempts()
        {
            DateTime start = new DateTime(2026, 1, 1, 16, 0, 0);

            List<LogEntry> logs = Enumerable.Range(0, 5)
                .Select(i => new LogEntry
                {
                    Timestamp = start.AddMinutes(i * 6),
                    Username = "testuser",
                    IPAddress = "192.168.1.70",
                    Status = "Failed",
                    EventType = "Login"
                })
                .ToList();

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsFalse(alerts.Any(a =>
                a.DetectionRule == "Repeated Failed Logins"));
        }

        // TEST 9: Success without preceding failures should not trigger compromise.
        [TestMethod]
        public void SuccessfulLoginWithoutPrecedingFailures_DoesNotTriggerCompromiseRule()
        {
            List<LogEntry> logs = new List<LogEntry>
            {
                new LogEntry
                {
                    Timestamp = new DateTime(2026, 1, 1, 17, 0, 0),
                    Username = "normaluser",
                    IPAddress = "192.168.1.80",
                    Status = "Success",
                    EventType = "Login"
                }
            };

            List<SecurityAlert> alerts = detectionEngine.Analyze(logs);

            Assert.IsFalse(alerts.Any(a =>
                a.DetectionRule == "Possible Account Compromise"));
        }

        // TEST 10: An empty log list should return no alerts.
        [TestMethod]
        public void EmptyLogList_ReturnsNoAlerts()
        {
            List<SecurityAlert> alerts =
                detectionEngine.Analyze(new List<LogEntry>());

            Assert.AreEqual(0, alerts.Count);
        }
    }
}
