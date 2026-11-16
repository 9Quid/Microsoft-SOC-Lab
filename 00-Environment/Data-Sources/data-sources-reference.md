# Data Sources

This document is a reference for the telemetry sources connected to the lab.

Before writing a KQL query, I use this page to check:

- Which connector produces the data
- Which table contains the data
- Whether the source is configured, active, or planned
- Whether live telemetry has been validated
- Any licensing or configuration requirements

The goal is to avoid guessing where data lives during an investigation.

---

## Status Definitions

The following status labels are used throughout this document:

- **Validated:** A query returned live data from the lab.
- **Active:** The connector or data source is enabled, but every listed table may not have been individually tested.
- **Configured:** The collection method has been deployed, but telemetry validation is still pending.
- **Planned:** The source is part of the lab roadmap but has not been fully connected.

A connector showing **Connected** is not treated as proof by itself.

For this lab, validation means:

**Connector enabled → Table available → Query executed → Live rows returned**

---

## Data Source Reference

| Source | Connector or Method | Key Tables | Status |
|---|---|---|---|
| Windows endpoints | Microsoft Defender for Endpoint | `DeviceInfo`, `DeviceNetworkInfo`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, `DeviceLogonEvents` | Validated |
| Domain controller endpoint | Defender for Endpoint, local onboarding script | Same `Device*` tables | Validated |
| Windows Security events | Azure Monitor Agent and Data Collection Rule | `SecurityEvent`, `Event` | Configured, validation pending |
| Active Directory identity | Microsoft Defender for Identity | `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | Validated |
| Entra ID sign-ins and audit | Microsoft Entra ID connector | `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` | Partially validated |
| Entra ID Protection | Microsoft Entra ID Protection | `AADRiskyUsers`, `AADUserRiskEvents` | Active, data dependent |
| Microsoft Defender alerts | Microsoft Defender XDR connector | `AlertInfo`, `AlertEvidence` | Active |
| Microsoft 365 email | Microsoft Defender XDR connector | `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents` | Active |
| Azure management plane | Azure Activity | `AzureActivity` | Validated |
| Cloud applications | Microsoft Defender for Cloud Apps | `CloudAppEvents` | Planned |
| Cloud resources | Microsoft Defender for Cloud | `SecurityRecommendation`, `SecurityAlert` | Planned |

---

## Windows Endpoints

### Connector

Microsoft Defender for Endpoint

### Onboarding Method

The hybrid-joined Windows clients were onboarded through an Intune Endpoint Detection and Response policy using:

```text
Package type: Auto from connector
```

### Key Tables

- `DeviceInfo`
- `DeviceNetworkInfo`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
- `DeviceLogonEvents`

### Investigation Uses

These tables support:

- Process and command-line investigation
- PowerShell investigation
- Network connection analysis
- File and registry activity
- User logon analysis
- Device inventory and operating system context
- Endpoint threat hunting

### Notes

These are the primary endpoint telemetry tables used throughout the lab.

Defender for Endpoint Plan 2 is required and is available through the Microsoft 365 E5 trial used for the lab.

`DeviceFileCertificateInfo` was intentionally left disabled because certificate-level file analysis is not currently required for the planned investigations. It can be enabled later if a malware or file-trust investigation needs signer and certificate context.

### Validation Status

Live data has been returned from all selected endpoint tables.

---

## Domain Controller Endpoint

### Connector

Microsoft Defender for Endpoint

### Onboarding Method

The domain controller was onboarded using the local onboarding script.

The domain controller is intentionally kept outside normal Intune device management in this lab.

### Key Tables

The domain controller produces the same Defender for Endpoint tables as the client devices, including:

- `DeviceInfo`
- `DeviceProcessEvents`
- `DeviceLogonEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`

### Notes

This provides endpoint visibility into the domain controller while keeping its administration separate from standard workstation management.

Defender for Endpoint records what happens on the server itself. Defender for Identity provides the separate Active Directory identity view.

---

## Windows Security Events

### Connector

Windows Security Events via Azure Monitor Agent

### Collection Method

**Windows event logs → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel**

### Key Tables

- `SecurityEvent`
- `Event`

### Useful Event IDs

- `4624`: Successful logon
- `4625`: Failed logon
- `4720`: User account created
- `4728`: Member added to a global security group
- `4732`: Member added to a local security group
- `4740`: User account locked out

### Investigation Uses

These tables support:

- Authentication investigations
- Account creation and modification analysis
- Group membership changes
- Account lockout investigations
- Traditional Sentinel analytics rules
- Cross-validation of Defender telemetry

### Notes

Windows Security events follow a different telemetry path from Defender XDR.

```text
Defender for Endpoint → Device* tables

Azure Monitor Agent → SecurityEvent and Event
```

The distinction matters because similar activity may appear differently across the two sources.

For example, a failed authentication may be investigated through:

- `SecurityEvent`
- `DeviceLogonEvents`
- `IdentityLogonEvents`
- `SigninLogs`

The correct table depends on where the authentication occurred and which product observed it.

### Validation Status

The AMA and DCR collection path is documented as configured.

Before changing this status to **Validated**, confirm that one or both of the following queries return live rows:

```kusto
SecurityEvent
| take 10
```

```kusto
Event
| take 10
```

If neither table returns data, the source should remain marked as **Configured, validation pending**.

---

## Active Directory Identity

### Connector

Microsoft Defender for Identity

### Collection Method

The unified Defender for Identity sensor is active on the domain controller.

### Key Tables

- `IdentityLogonEvents`
- `IdentityQueryEvents`
- `IdentityDirectoryEvents`

### Investigation Uses

These tables support:

- Password spray investigation
- Kerberoasting investigation
- Active Directory reconnaissance
- Directory object changes
- Authentication correlation
- Identity-focused threat hunting

### Table Roles

#### `IdentityLogonEvents`

Contains authentication activity involving on-premises Active Directory.

#### `IdentityQueryEvents`

Contains information about queries performed against Active Directory objects.

This is useful when investigating reconnaissance or unusual directory queries.

#### `IdentityDirectoryEvents`

Contains identity and directory-related events, including changes involving users, groups, and other directory objects.

### Validation Status

All three identity tables have returned live data from the lab.

---

## Entra ID Sign-ins and 