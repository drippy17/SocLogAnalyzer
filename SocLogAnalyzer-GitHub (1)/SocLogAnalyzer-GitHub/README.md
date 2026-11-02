# SOC Log Analyzer

A Windows desktop application built with C# and WPF to import authentication log files, identify suspicious login activity, and support basic security-alert investigations.

## Project overview

SOC Log Analyzer is a defensive security-operations prototype. It analyses authentication events and highlights patterns that may warrant investigation by a security analyst.

## Features

- Import CSV-style authentication log files.
- Display log and alert information in a WPF dashboard.
- Detect repeated failed logins from the same username and IP address.
- Detect possible password spraying from one IP address across multiple usernames.
- Detect possible account compromise when repeated failures are followed by a successful login.
- Classify alerts as Medium or High based on the implemented thresholds.
- View alert evidence and recommended investigation information.
- Track investigation status, analyst, notes, timestamps and history.
- Persist investigation records locally in JSON.
- Filter log and alert data and export a report.
- Review the configured detection rules in the application.

## Technology

- C#
- .NET 8 (`net8.0-windows`)
- Windows Presentation Foundation (WPF)
- LiveChartsCore.SkiaSharpView.WPF 2.0.5
- MSTest

## Solution structure

- `SocLogAnalyzer/` — WPF desktop application.
- `SocLogAnalyzer.Tests/` — MSTest project containing detection-engine tests.
- `SocLogAnalyzer/SocLogAnalyzer/` — application source files and sample log files.

## Detection rules

| Rule | Implemented behaviour |
|---|---|
| Repeated Failed Logins | Groups failed logins by username and IP address within a five-minute window. Medium threshold: 5 attempts; High threshold: 10 attempts. |
| Possible Password Spraying | Looks for failed logins from one IP address against distinct usernames within a five-minute window. Medium threshold: 5 usernames; High threshold: 10 usernames. |
| Possible Account Compromise | Flags a successful login when at least 5 failures for the same username and IP address occurred in the preceding five minutes. |

These are heuristic detection rules for a prototype. An alert is an indicator for review, not proof that an account has been compromised.

## Log file format

The parser expects comma-separated rows with five fields:

`timestamp,username,ip_address,status,event_type`

Example:

`2026-10-27 09:15:00,alex,192.0.2.10,Failed,Login`

The included `.txt` files provide sample data for testing the application.

## Requirements

- Windows
- Visual Studio 2022 with the .NET desktop development workload
- .NET 8 SDK

## Run the application

1. Clone or download this repository.
2. Open `SocLogAnalyzer.sln` in Visual Studio 2022.
3. Allow NuGet packages to restore.
4. Set `SocLogAnalyzer` as the startup project if it is not already selected.
5. Run the application with **F5**.
6. Use **Import Log File** to select one of the sample `.txt` files, then select **Analyze Logs**.

## Run the tests

1. Open the solution in Visual Studio 2022.
2. Open **Test > Test Explorer**.
3. Build the solution.
4. Select **Run All** in Test Explorer.

The test project contains 10 MSTest test methods covering detection thresholds, time windows, password spraying, account-compromise indicators and empty/no-alert cases.

## Investigation data

Investigation records are stored locally under the current Windows user's Local Application Data folder, in:

`%LOCALAPPDATA%/SocLogAnalyzer/investigations.json`

This is local application data and is not automatically synchronised to GitHub.

## Limitations and responsible use

- The detection logic uses simple thresholds and time windows; it can produce false positives and may miss activity outside its rules.
- The parser is designed for the included five-field comma-separated format, not every vendor's log format.
- This prototype analyses imported logs; it is not a live network-monitoring or SIEM platform.
- Do not upload real usernames, IP addresses, credentials or confidential organisational logs to a public repository. Use sanitised sample data.

## Author

Add your name and contact/profile links here before publishing.
