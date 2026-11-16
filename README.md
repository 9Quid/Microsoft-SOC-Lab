# Microsoft Defender and Sentinel SOC Lab
 
I built this lab to learn how a Security Operations Center (SOC) works in practice.

When I started learning Microsoft security technologies, I found plenty of resources explaining how to deploy tools. What I wanted to understand was everything that happens afterwards.
 
How does an alert get generated?
 
How do you investigate it?
 
How do you know if it's a real threat?
 
This repository documents my attempt to answer those questions by building and operating my own Microsoft-focused SOC lab.

## Lab overview

Active Directory and Entra ID feed Microsoft Defender XDR, which feeds Microsoft Sentinel, where detections are investigated.

The goal isn't just to generate alerts — it's to understand the full lifecycle:

**Activity → Detection → Investigation → Response → Case Management → Lessons Learned**

## What's included

### [`00-Environment/`](00-Environment/)

How the lab was built and validated: build notes, data source
reference, and health-check validation.

### [`01-Investigations/`](01-Investigations/)

Case studies, each following the same process — alert, evidence collection,
investigation, assessment, response.

| Investigation |
|---|
| [Password Spray](01-Investigations/01-Password-Spray/) — repeated auth failures across accounts |
| [Kerberoasting](01-Investigations/02-Kerberoasting/) — suspicious Kerberos service ticket activity |

### [`02-Incident-Response/`](02-Incident-Response/) 

What happens after detection: containment, remediation, recovery, validation.

## Repository structure

```
SOC-Lab/
├── 00-Environment/
│   ├── Build-Notes/
│   ├── Data-Sources/
│   └── Validation/
├── 01-Investigations/
│   ├── 01-Password-Spray/
│   ├── 02-Kerberoasting/
├── 02-Incident-Response/
│   ├── Containment/
│   ├── Remediation/
│   └── Recovery/
```

## Why I built this

I'm still early in my cybersecurity journey, and one thing became obvious fast: this field doesn't really treat itself as entry-level. Nearly every posting wants experience with real tools, real investigations, real incidents; the kind of experience that's hard to get before someone gives you the job that would give it to you.

Rather than wait out that paradox, I built the experience myself.

Instead of reading about attacks, I wanted to run them. Instead of learning what a SOC analyst does, I wanted to do it. Instead of following a tutorial end to end, I wanted to build something, break it, and figure out why; which happened more than once, including a Group Policy chase that turned out to be a Conditional Access issue, and an accidental domain controller rename that taught me more about Active Directory internals than any course would have.

Along the way I've worked with Active Directory, Entra ID, Defender XDR, Defender for Identity, Sentinel, Logic Apps, Intune, KQL, and Jira, not just by reading documentation but by getting them to work together, generating telemetry, investigating alerts, and troubleshooting issues when things inevitably broke.

This repository isn't meant to present me as an expert. It's meant to document the process of becoming one. It's meant to show how I think, investigate, and document findings.

Build → Break → Detect → Investigate → Fix → Learn.

If this shows anything, I hope it's curiosity, the willingness to learn, and get my hands dirty until something makes sense.

**Build → Break → Detect → Investigate → Fix → Learn.**

Every project here follows that same loop.