# Phishing Triage Workflow Diagram

```
┌─────────────────────┐
│  Email Reported as   │
│     Suspicious       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Shuffle Webhook     │
│  Receives Alert      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Extract IOCs        │
│  • Sender IP/Email   │
│  • URLs in body      │
│  • Attachment hashes  │
└──────────┬──────────┘
           │
     ┌─────┼─────┐
     │     │     │
     ▼     ▼     ▼
┌────────┐ ┌────────┐ ┌────────┐
│VT URL  │ │AbuseIP │ │VT Hash │
│Lookup  │ │Sender  │ │Lookup  │
│        │ │Check   │ │        │
└───┬────┘ └───┬────┘ └───┬────┘
    │          │          │
    └──────────┼──────────┘
               │
               ▼
┌─────────────────────┐
│  Aggregate Results   │
│  Calculate Risk      │
└──────────┬──────────┘
           │
     ┌─────┼─────────────┐
     │     │             │
     ▼     ▼             ▼
┌────────┐ ┌──────────┐ ┌──────────┐
│ LOW    │ │ MEDIUM   │ │ HIGH     │
│All     │ │1+ suspect│ │Known     │
│clean   │ │indicator │ │malicious │
└───┬────┘ └────┬─────┘ └────┬─────┘
    │           │             │
    ▼           ▼             ▼
┌────────┐ ┌──────────┐ ┌──────────┐
│Auto-   │ │ ANALYST  │ │Escalate  │
│close   │ │ REVIEW   │ │Immediate │
│case    │ │ Required │ │Block IOCs│
└────────┘ └────┬─────┘ └────┬─────┘
                │             │
                └──────┬──────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Create TheHive  │
              │ Case with all   │
              │ enrichment data │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Webhook Notify  │
              │ SOC Channel     │
              └─────────────────┘
```
