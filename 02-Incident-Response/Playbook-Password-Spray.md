# Incident Response: Password Spray

Response steps for the [Password Spray investigation](../01-Investigations/01-Password-Spray/README.md). In the lab no containment was needed because the activity was an authorized test. This playbook records what the response would be in a real environment.

| Field | Value |
|---|---|
| Trigger | Custom Defender XDR detection "Possible Password Spraying Activity" |
| MITRE ATT&CK | T1110.003 Password Spraying |
| Pattern | One source IP, multiple accounts, `LogonFailed` / `WrongPassword`, short time window |
| Lab outcome | No successful authentication; benign true positive |

## 1. Triage: is it real?

- Do the failures come from one source IP across several accounts (spray), or many failures against one account (brute force)?
- Is the source IP known (a scanner, a misconfigured service, a user's device) or unexpected?
- Are the targeted accounts related (same department, same naming pattern)?

## 2. Scope

- List every account the source IP targeted, and the time range.
- Check each targeted account for a **successful** logon after the failures. This decides the severity.
- Check whether the same source IP touched other hosts or accounts.

## 3. Contain

**If no account authenticated (this lab):**

- Record the evidence and close as benign or false positive, with notes.
- Block or monitor the source IP if it is not a legitimate host.

**If any account authenticated successfully:**

- Treat it as a compromise. Reset the account password and revoke active sessions.
- Review what the account did after the logon (mail rules, file access, new devices).
- Confirm MFA is enforced on the account.
- Escalate to the incident lead.

## 4. Recover and verify

- Confirm the source IP can no longer authenticate, and that no further failures appear.
- Confirm the affected accounts show normal logon patterns for the following days.

## 5. Escalate when

- Any targeted account has a successful logon from the source.
- A privileged or Finance account is among the successes.
- The source is an external or unknown IP.

## 6. Post-incident

- Check the detection threshold (the lab rule fires at four accounts from one source) and tune it if needed.
- Confirm MFA coverage and review account lockout settings.
- Review how the alerts were generated: four standalone alerts were never grouped into one incident.
