# Incident Response: Kerberoasting

Response steps for the [Kerberoasting investigation](../01-Investigations/02-Kerberoasting/README.md). In the lab, the containment and remediation steps below were carried out against the test account `svc-sqlservice`.

| Field | Value |
|---|---|
| Trigger | Defender for Identity "Possible Kerberoasting" alerts, grouped into one Defender XDR incident |
| MITRE ATT&CK | T1558.003 Kerberoasting, T1087 Account Discovery, T1078 Valid Accounts |
| Pattern | A domain account enumerates SPNs and requests an RC4 (0x17) service ticket for a service account |
| Lab outcome | Password recovered offline; account compromised; fully remediated |

## 1. Triage: is it real?

- Which account requested the service ticket, from which host, and is that normal for them?
- Was the ticket RC4 (`0x17`) when the domain controller supports AES?
- Were several SPNs requested in a short window?

## 2. Scope

- Look for successful logons by the targeted service account (Event 4624) after the ticket request.
- Check for newly installed services (Event 4697) to rule out persistence.
- Check whether the requesting host or account appears in other alerts.

## 3. Contain

Preserve evidence (export the alert, incident and logs) **before** changing anything.

- Reset the service account password (done in the lab with `Set-ADAccountPassword`).
- Disable the old account once the service has moved.
- Isolate the requesting host if it is compromised.

## 4. Eradicate and recover

- Migrate the service to a **group Managed Service Account (gMSA)** so the password is automatic and not guessable (done: `svc-sql-gmsa`).
- Enforce AES256 on the new account (done: `Set-ADServiceAccount -KerberosEncryptionType AES256`).
- Move the SPN to the new account and confirm the SQL Server service still works.
- Related hardening from the lab: restrict anonymous access (`RestrictAnonymous = 1`).

## 5. Verify

- **Done in the lab:** the same attack against the reset account with the original wordlist recovered nothing (0/1).
- **Done in the lab:** the SPN, account state and `msDS-GroupManagedServiceAccount` class were checked after migration.
- Recommended: request a new service ticket and confirm it is AES (`0x12`), not RC4 (`0x17`).
- Monitor for further RC4 ticket requests (Event 4769) over the following days.

## 6. Escalate when

- The targeted account is privileged, or has logged on from unexpected hosts.
- The password was recovered and the account has been used.
- There are signs of persistence or lateral movement.

## 7. Post-incident

- Replace manually managed service account passwords with gMSAs wherever possible.
- In production, point the gMSA at a security group (not a single computer account).
- Alert on RC4 ticket requests for service accounts.
- Lesson: a password reset fixes the immediate compromise; the lasting fix is removing the weak password and the RC4 option.
