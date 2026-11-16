## Defender for Identity

Most of the attacks I wanted to practice in this lab are identity-focused.

Onboarding the domain controller to Defender for Endpoint gave me visibility into the server itself, but it did not provide visibility into Active Directory authentication activity.

To monitor identity-related activity, I enabled Microsoft Defender for Identity on the domain controller after confirming that Defender for Endpoint onboarding had completed successfully.

### Why Defender for Identity?

Defender for Endpoint focuses on the device.

Examples include:

- Process execution
- PowerShell activity
- File activity
- Network connections
- Endpoint alerts

Defender for Identity focuses on authentication and identity signals within Active Directory.

Examples include:

- Kerberos authentication
- NTLM authentication
- Password spraying
- Kerberoasting
- Active Directory reconnaissance
- Suspicious account behaviour

Together, the two products provide visibility from both the endpoint and identity perspectives.

```text
Domain Controller
├── Defender for Endpoint
│   └── Endpoint telemetry
│
└── Defender for Identity
    └── Identity telemetry
```

### Activation

The domain controller was already onboarded to Defender for Endpoint, which is a prerequisite for the modern unified Defender for Identity sensor.

Once the server appeared in Microsoft Defender, Defender for Identity was activated through the Defender portal rather than using the older standalone sensor deployment method.

Licensing was confirmed beforehand, since Defender for Identity requires Microsoft 365 E5 or an equivalent add-on.

### Why It Matters For This Lab

Several planned investigations depend on identity telemetry rather than endpoint telemetry.

These include:

1. Password Spray
2. Kerberoasting
3. Cloud Identity Investigation
4. Authentication Correlation
5. Identity Threat Hunting

Without Defender for Identity, a large portion of the authentication and Active Directory visibility required for those exercises would be missing.

Adding Defender for Identity moved the lab beyond endpoint monitoring and closer to the type of hybrid environment a SOC analyst would encounter in a real organisation.

### What I Learned

Before building this lab, I thought about security mostly from the endpoint perspective.

Defender for Identity helped reinforce how important identity is within modern environments.

Users, service accounts, authentication flows, privileged groups, and trust relationships are often the real targets during an attack.

The more time I spend working with identity telemetry, the more I understand why so many modern attacks focus on credentials rather than malware.

Sensor status, health, and identity telemetry confirmation are documented in:

```text
00-Environment/Validation/
```