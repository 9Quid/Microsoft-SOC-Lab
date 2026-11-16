## Log Analytics Workspace

I created a Log Analytics workspace before enabling Microsoft Sentinel.

The workspace provides the Azure-based data layer used by Sentinel for querying, analytics, investigation, and retention.

Creating the workspace first also gave me a place to configure cost controls before connecting security data sources.

---

## Microsoft Sentinel

Microsoft Sentinel was enabled on top of the Log Analytics Workspace.

The initial data connectors enabled for the lab were:

- Microsoft Defender XDR
- Microsoft Defender for Identity
- Azure Activity

These connectors were chosen because they align directly with the investigation scenarios planned later in the project, including identity attacks, endpoint investigations, privilege changes, and Azure administration activity.

The intended flow is:

**Endpoints / Identities / Azure Activity
→ Microsoft Sentinel
→ Analytics Rules
→ Incidents
→ Investigation**

The connectors support the wider lab by bringing endpoint, identity, and cloud administration signals into a single investigation environment.

This allows me to use Sentinel for:

- KQL investigations
- Analytics rules
- Incident creation
- Threat hunting
- Automation
- Case-management integration

The detailed connector configuration and telemetry validation checks are documented in the validation section rather than repeated here.