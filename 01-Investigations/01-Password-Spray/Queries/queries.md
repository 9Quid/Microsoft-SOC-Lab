# Password Spray Investigation Queries

This document contains the KQL queries used during the password spray investigation.

The goal of these queries was to validate the telemetry, confirm the attack pattern, establish scope, determine whether any authentication succeeded, and prepare a detection capable of generating a Microsoft Sentinel incident.

---

## 01 – Raw Event Validation

### Goal

Validate raw failed authentication events from the suspected source and confirm the available telemetry fields.

### Query

```kusto
let TargetIP = "192.168.1.50";
let Lookback = 24h;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where IPAddress == TargetIP
| where ActionType == "LogonFailed"
| project
    Timestamp,
    ActionType,
    Protocol,
    IPAddress,
    AccountUpn,
    AccountName,
    DeviceName,
    FailureReason
| order by Timestamp desc
```

### Purpose

Used to confirm:

- Failed authentication activity exists
- Source IP is present
- Account information is available
- Authentication protocol is available
- Failure reason is recorded

---

## 02 – Password Spray Pattern Validation

### Goal

Confirm that the activity matches the shape of a password spray attack.

### Query

```kusto
let Lookback = 24h;
let AccountThreshold = 4;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where ActionType == "LogonFailed"
| where isnotempty(IPAddress)
| extend TargetAccount = coalesce(AccountUpn, AccountName)
| where isnotempty(TargetAccount)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TotalFailedAttempts = count(),
    UniqueTargetedUsers = dcount(TargetAccount),
    TargetedAccountsList = make_set(TargetAccount, 100)
    by IPAddress, Protocol
| where UniqueTargetedUsers >= AccountThreshold
| sort by UniqueTargetedUsers desc
```

### Purpose

Used to determine:

- Number of affected accounts
- Number of failed authentications
- Authentication protocol
- First and last observed activity

### Expected Result

One source IP targeting multiple accounts within a short period.

---

## 03 – Timeline Reconstruction

### Goal

Build a chronological timeline of authentication activity.

### Query

```kusto
let TargetIP = "192.168.1.50";
let Lookback = 24h;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where IPAddress == TargetIP
| extend TargetAccount = coalesce(AccountUpn, AccountName)
| project
    Timestamp,
    ActionType,
    TargetAccount,
    IPAddress,
    Protocol,
    FailureReason,
    Application
| sort by Timestamp asc
```

### Purpose

Used to:

- Determine attack timing
- Measure attack velocity
- Support timeline creation

---

## 04 – Scope Assessment

### Goal

Determine the full blast radius of the activity.

### Query

```kusto
let TargetIP = "192.168.1.50";
let Lookback = 24h;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where IPAddress == TargetIP
| extend TargetAccount = coalesce(AccountUpn, AccountName)
| summarize
    TotalAttempts = count(),
    FailedCount = countif(ActionType == "LogonFailed"),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FirstAttempt = min(Timestamp),
    LastAttempt = max(Timestamp),
    UsedProtocols = make_set(Protocol),
    TargetedApps = make_set(Application)
    by TargetAccount, IPAddress
| sort by FailedCount desc
```

### Purpose

Used to identify:

- Every targeted account
- Protocols used
- Applications involved
- Authentication outcomes

---

## 05 – Successful Authentication Check

### Goal

Determine whether the password spray resulted in successful authentication.

### Query

```kusto
let TargetIP = "192.168.1.50";
let Lookback = 24h;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where IPAddress == TargetIP
| where ActionType == "LogonSuccess"
| extend TargetAccount = coalesce(AccountUpn, AccountName)
| project
    Timestamp,
    ActionType,
    TargetAccount,
    IPAddress,
    Protocol,
    Application,
    DeviceName
| sort by Timestamp asc
```

### Purpose

This is the most important validation query in the investigation.

Used to determine:

- Whether any account authenticated successfully
- Whether the incident should be escalated
- Whether containment actions would be required

### Investigation Result

No successful authentication observed during the investigation window.

---

## 06 – Related Activity Review

### Goal

Search for activity associated with successfully authenticated accounts.

### Query

```kusto
let TargetIP = "192.168.1.50";
let Lookback = 24h;

let CompromisedAccounts =
    IdentityLogonEvents
    | where Timestamp > ago(Lookback)
    | where IPAddress == TargetIP
    | where ActionType == "LogonSuccess"
    | extend TargetAccount = coalesce(AccountUpn, AccountName)
    | summarize by TargetAccount;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where AccountUpn in (CompromisedAccounts)
    or AccountName in (CompromisedAccounts)
| where IPAddress != TargetIP
| project
    Timestamp,
    ActionType,
    AccountUpn,
    AccountName,
    IPAddress,
    Application,
    Location
| sort by Timestamp asc
```

### Purpose

Used only if successful authentication has been identified.

Checks for:

- Follow-on activity
- Account reuse
- Signs of compromise
- Lateral movement

### Investigation Result

No successful authentication was observed, so no related follow-on activity was identified.

---

## 07 – Custom Detection Query

### Goal

Generate an alertable password spray detection suitable for a Microsoft Sentinel analytics rule.

### Query

```kusto
let Lookback = 5h;
let AccountThreshold = 4;

let SpraySources =
    IdentityLogonEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "LogonFailed"
    | where isnotempty(IPAddress)
    | extend TargetAccount = coalesce(AccountUpn, AccountName)
    | where isnotempty(TargetAccount)
    | summarize
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        FailedCount = count(),
        TargetUserCount = dcount(TargetAccount),
        TargetAccounts = make_set(TargetAccount, 50)
        by IPAddress
    | where TargetUserCount >= AccountThreshold;

IdentityLogonEvents
| where Timestamp > ago(Lookback)
| where ActionType == "LogonFailed"
| where isnotempty(IPAddress)
| extend TargetAccount = coalesce(AccountUpn, AccountName)
| where isnotempty(TargetAccount)
| join kind=inner SpraySources on IPAddress
| summarize
    Timestamp = max(Timestamp),
    ReportId = any(ReportId),
    FirstSeen = min(FirstSeen),
    LastSeen = max(LastSeen),
    FailedCount = max(FailedCount),
    TargetUserCount = max(TargetUserCount),
    TargetAccounts = any(TargetAccounts),
    DeviceName = any(DeviceName),
    DestinationDeviceName = any(DestinationDeviceName),
    Protocol = any(Protocol),
    FailureReason = any(FailureReason)
    by IPAddress, TargetAccount, AccountName, AccountDomain
| project
    Timestamp,
    ReportId,
    IPAddress,
    TargetAccount,
    AccountName,
    AccountDomain,
    TargetUserCount,
    FailedCount,
    DeviceName,
    DestinationDeviceName,
    Protocol,
    FailureReason,
    FirstSeen,
    LastSeen
```

### Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Name | Possible Password Spraying Activity |
| Severity | Medium |
| MITRE ATT&CK | T1110.003 |
| Run Frequency | 5 Minutes |
| Lookback Window | 5 Hours |
| Threshold | 4 Unique Accounts |
| Incident Creation | Enabled |

### Entity Mapping

| Entity | Identifier | Column |
|---|---|---|
| User | UPN | TargetAccount |
| IP Address | Address | IPAddress |
| Host | Host Name | DestinationDeviceName |

### Result

Successfully generated a Microsoft Defender XDR incident using controlled password spray activity against four Finance department accounts.