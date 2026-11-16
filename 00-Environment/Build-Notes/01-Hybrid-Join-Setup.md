# Hybrid Join Setup

## Licensing and Cost

### Microsoft 365 E5 Trial

A lot of the Microsoft security features I wanted to explore are locked behind higher licensing tiers.

I used a Microsoft 365 E5 trial to gain access to:

- Defender for Endpoint Plan 2
- Defender for Identity
- Defender for Cloud Apps
- Entra ID Protection (P2)

Without these licences, a large part of this lab simply would not have been possible.

The trial gave me access to the same tools and telemetry that many enterprise SOC teams use for endpoint, identity, and cloud investigations.

---

### Azure Free Trial

Microsoft Sentinel requires an Azure subscription, so I also used an Azure free trial for the cloud components of the lab.

The Azure credits were used for:

- Log Analytics Workspace
- Microsoft Sentinel
- Future cloud resources and test workloads

One lesson I learned early was that cloud costs can add up quickly if you're not paying attention.

To avoid surprises, I configured a daily data cap on the Log Analytics Workspace as soon as Sentinel was deployed.

It was a small step, but it helped me start thinking about lab management the same way an administrator would think about managing a real environment.

---

## What Was Built

- On-premises Active Directory domain (`9quid.local`)
- A dedicated OU structure:

```text
Hybrid-Cloud-Lab
├── Users
├── Computers
└── Groups
```

- Microsoft Entra Cloud Sync syncing users and groups into Microsoft Entra ID
- A verified custom tenant domain (`9quidsecurity.com`)
- Matching UPN suffixes on all synced accounts
- A Service Connection Point (SCP) enabling hybrid join for domain-joined devices
- `redircmp` configured so newly joined computers land directly in the Computers OU

At a high level, the identity flow looks like this:

```text
Active Directory → Microsoft Entra Cloud Sync → Microsoft Entra ID → Hybrid Identity
```

---

## Key Issue and Fix

One issue I ran into during the hybrid identity setup was UPN mapping.

UPNs must use the verified custom domain, not the on-premises Active Directory suffix (`.local`).

Using the AD suffix as an identity string can cause:

```text
AADSTS90002
Tenant not found
```

This happens because Microsoft Entra attempts to resolve the value as a tenant domain.

The fix was straightforward:

```text
Incorrect: user@9quid.local

Correct:   user@9quidsecurity.com
```

After updating the UPN suffixes and allowing synchronization to complete, hybrid identity functionality worked as expected.

---

## Verification Commands Used

These were the main commands I used to validate the environment during and after deployment.

```powershell
dsregcmd /status
nltest /dsgetdc:9quid.local
Get-ADComputer -Identity <computer-name>
```

Checks performed:

- `dsregcmd /status` verifies AzureAdJoined, DomainJoined, and PRT status.
- `nltest /dsgetdc:9quid.local` verifies domain controller discovery.
- `Get-ADComputer` verifies OU placement and computer object status.

---

## Incident: Accidental Domain Controller Rename

This was probably the most expensive mistake I made during the hybrid identity build.

I learned that `Rename-Computer` has no domain controller awareness. It will rename a domain controller exactly like it would a workstation, with no warning.

This happened once in the lab due to a mistyped remote session target.

The recovery involved using the proper `netdom computername` sequence instead of a standard rename.

```text
Add New Name → Make Primary → Remove Old Name
```

Using the supported process preserves:

- Service Principal Names (SPNs)
- DNS records
- Replication metadata

It was an annoying mistake to make, but it ended up being one of the more valuable lessons from the entire build.