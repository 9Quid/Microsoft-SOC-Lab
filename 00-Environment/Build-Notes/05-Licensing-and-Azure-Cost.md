## Azure Cost Management

One lesson I learned early is that cloud resources are easy to deploy and easy to forget about.

Because this lab uses Azure trial credit, I added cost controls before connecting data sources or generating large amounts of telemetry.

### Azure Budget

I created a subscription-level budget for the lab.

```text
Budget name: SOC-Lab-Budget
Scope: Subscription
Reset period: Monthly
```

Budget alerts were configured at:

1. 50 percent
2. 75 percent
3. 90 percent
4. 100 percent

The purpose of the budget is not to stop services automatically.

It gives me an early warning if resource usage or data ingestion begins consuming more credit than expected.

### Log Analytics Daily Cap

Microsoft Sentinel costs are closely connected to data ingestion through the Log Analytics workspace.

I therefore configured a daily data cap before connecting the main data sources.

The cap provides a guardrail if:

- A connector becomes noisy
- A configuration sends more events than expected
- Testing produces a sudden increase in telemetry
- A resource is left running unintentionally

A daily cap can also interrupt ingestion after the limit is reached, so I treat it as a safety control rather than a replacement for monitoring usage.

### Why Cost Management Belongs in the Build Notes

Before building this lab, I mostly thought about security tools from a detection and investigation perspective.

The Azure side of the project introduced another set of questions:

1. How much data am I collecting?
2. Which data sources are actually useful?
3. What happens if ingestion increases unexpectedly?
4. How will I know when spending is approaching the available credit?
5. Can I reduce unnecessary telemetry without losing important visibility?

This reminded me that a security platform still needs to be operated and maintained.

Even in a lab, cost awareness is part of building responsibly.

---

## Licensing Notes

Some parts of the lab depend on features that are not available in lower licensing tiers.

The Microsoft 365 E5 trial provides access to the security capabilities used in this stage of the build, including:

- Defender for Endpoint Plan 2
- Defender for Identity
- Defender for Cloud Apps
- Entra ID Protection P2

Defender for Endpoint Plan 2 is also important for the endpoint hunting tables used later in the project, including tables such as:

```kusto
DeviceLogonEvents
```

Checking licensing early helped me avoid treating a licensing limitation as a sensor, data, or connector failure.

---

## What I Learned

This stage of the build helped me understand that onboarding is not a single action.

Several separate layers must work together:

1. The device must be onboarded.
2. The local security component must be healthy.
3. The device must communicate with Defender XDR.
4. The required licence must be assigned.
5. The correct connector must be enabled.
6. The expected telemetry must reach the investigation platform.
7. Cost controls must be in place before data volume increases.

A device appearing in one portal does not automatically prove that the full monitoring path is working.

That proof belongs in the validation section, where each layer is tested separately.

The build path for this stage was:

**Endpoint Onboarding → Identity Sensor Activation → Defender XDR → Log Analytics → Microsoft Sentinel → Cost Controls**