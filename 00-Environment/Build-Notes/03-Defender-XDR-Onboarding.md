# Defender XDR and Microsoft Sentinel Onboarding

This stage of the build connected the lab devices to Microsoft Defender XDR and brought the resulting security data into Microsoft Sentinel.

The goal was to create one investigation path across endpoint, identity, and cloud security signals:

**Lab Devices → Defender XDR → Microsoft Sentinel → Investigation**

---

## Devices Onboarded

The domain controller and hybrid-joined client devices were onboarded using different methods.

### Domain Controller

The domain controller was onboarded to Microsoft Defender for Endpoint using the local onboarding script.

I intentionally kept the domain controller outside normal Intune device management in this lab. Domain controllers have a different role and risk profile from standard workstations, so I wanted to manage the onboarding process separately.

### Hybrid-Joined Clients

The client virtual machines were onboarded through an Intune Endpoint Detection and Response policy.

The policy used:

```text
Package type: Auto from connector
```

This allowed Intune-managed devices to receive their Defender for Endpoint onboarding configuration automatically.

The final onboarding approach was:

| Device type | Onboarding method |
|---|---|
| Domain controller | Local onboarding script |
| Hybrid-joined client VMs | Intune Endpoint Detection and Response policy |

This gave me experience with both direct onboarding and centrally managed onboarding.

---

## Microsoft Defender XDR

After onboarding, Microsoft Defender XDR became the main place for reviewing endpoint alerts, device activity, incidents, and advanced hunting data.

The client devices provide endpoint telemetry such as:

- Process creation
- PowerShell activity
- File activity
- Network connections
- User logons
- Security alerts

This telemetry supports later investigations involving suspicious PowerShell, phishing-related endpoint activity, authentication events, and possible post-compromise behaviour.

The detailed confirmation that the devices were onboarded and reporting is documented separately in:

```text
00-Environment/Validation/
```