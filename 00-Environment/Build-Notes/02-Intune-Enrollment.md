# Intune MDM Enrollment

## What I Was Trying To Do

One of the goals of the lab was to manage hybrid joined devices through Microsoft Intune.

To support this, I configured automatic MDM enrollment for domain-joined devices so they would enroll into Intune after hybrid joining Microsoft Entra ID.

---

## What Was Built

The following settings were configured:

### Group Policy

```text
Computer Configuration
└── Administrative Templates
    └── Windows Components
        └── MDM
```

- Enable automatic MDM enrollment using default Azure AD credentials = **Enabled**
- Credential type = **User Credential**
- Disable MDM Enrollment = **Disabled**

### Entra ID

- MDM user scope assigned to a licensed user group
- Users licensed for Intune and Entra ID Premium features

### Validation

I verified the configuration using:

```powershell
dsregcmd /status
```

and:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM
```

Both confirmed that policy application was working as expected.

---

## The Problem

Despite the policy being applied correctly, the device would not enroll into Intune.

Running:

```powershell
dsregcmd /status
```

showed:

```text
PolicyEnabled : NO
PreReqResult  : WillNotProvision
```

At this point the issue clearly wasn't the GPO itself because the policy and registry settings were already present.

Something later in the enrollment process was failing.

---

## Investigation

The breakthrough came from reviewing the Intune enrollment logs instead of focusing on the summary status.

I checked:

```text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── DeviceManagement-Enterprise-Diagnostics-Provider
            └── Admin
```

Several events pointed to the same error:

```text
0x8018002a
```

The logs included:

```text
Auto MDM Enroll Get AAD Token
Status: 0x8018002a
```

and

```text
Auto MDM Enroll Impersonation Failure
0x82aa0008
```

The important observation was that enrollment was reaching the authentication stage before failing.

This meant:

```text
GPO Configuration ✓
Registry Configuration ✓
Enrollment Request ✓
Authentication ✗
```

The enrollment process was being blocked while attempting to obtain a token.

---

## Root Cause

The signing-in user had never completed MFA registration.

Because the enrollment policy was configured to use:

```text
User Credential
```

the enrollment request ran in the context of the signed-in user.

That request needed to satisfy the tenant's authentication requirements before a token could be issued.

Without MFA registration, the enrollment request had no valid authentication method available and failed during token acquisition.

One thing that initially caused confusion was the log entry:

```text
Auto MDM Enroll: Device Credential (0x0)
```

This turned out to be a fixed label used by Windows diagnostics and did not reflect the actual GPO configuration.

The configured enrollment method was confirmed directly from Group Policy and was still set to:

```text
User Credential
```

---

## Fix

The user completed MFA registration:

```text
https://aka.ms/mfasetup
```

After registration, I forced a clean enrollment attempt.

```powershell
dsregcmd /leave
```

The device was then restarted and the user signed back in.

---

## Verification

Reviewing the same event logs now showed successful token acquisition.

```text
Auto MDM Enroll Get AAD Token
Status: The operation completed successfully.
```

Additional events confirmed successful enrollment:

```text
Certificate policy request sent successfully
Certificate policy response processed successfully
```

and

```text
TPM State: Ready
```

The device appeared in Intune within minutes as:

```text
Hybrid Joined
Managed
```

To make sure the result wasn't accidental, I repeated the process with a second user and observed the same before-and-after behavior.

---

## Incorrect Assumption I Had To Correct

During troubleshooting I initially believed success was linked to moving the user into the Computers OU.

Later testing disproved that theory.

A second user enrolled successfully while remaining in the normal Users OU for the entire process.

The timing simply happened to overlap with MFA registration, which made it look like the OU change had fixed the problem.

In reality:

```text
OU Move             ✗ Not Required
MFA Registration    ✓ Required
```

---

## What I Learned

This issue reinforced an important lesson:

When troubleshooting hybrid identity and Intune enrollment, don't stop at:

```powershell
dsregcmd /status
```

The summary flags only tell you that enrollment failed.

The real answer is usually found in:

```text
DeviceManagement-Enterprise-Diagnostics-Provider
```

In this case the problem wasn't Group Policy, Entra ID sync, hybrid join, or Intune configuration.

The problem was an authentication requirement that had not been satisfied by the user account.

Looking at the enrollment logs made that visible almost immediately.