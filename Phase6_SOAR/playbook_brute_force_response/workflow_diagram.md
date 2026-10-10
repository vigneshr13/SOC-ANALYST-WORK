# Brute Force Response Workflow Diagram

```
┌─────────────────────┐
│ Splunk Alert:        │
│ 10+ Failed Logins   │
│ from Single Source   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Shuffle Webhook      │
│ Extract Source IP    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Is Source IP         │
│ Internal?            │
└──────┬───────┬──────┘
       │       │
  YES  │       │  NO
       ▼       ▼
┌────────┐ ┌─────────────────┐
│ESCALATE│ │ AbuseIPDB       │
│Do NOT  │ │ Reputation      │
│auto-   │ │ Check           │
│block   │ └────────┬────────┘
└────────┘          │
              ┌─────┴─────┐
              │           │
         Score > 50  Score ≤ 50
              │           │
              ▼           ▼
     ┌──────────┐  ┌──────────┐
     │AUTO-BLOCK│  │ ANALYST  │
     │in pfSense│  │ REVIEW   │
     └────┬─────┘  └────┬─────┘
          │              │
          └──────┬───────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Create TheHive  │
        │ Case with:      │
        │ • Alert details │
        │ • IP reputation │
        │ • Block action  │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Webhook Notify  │
        │ SOC Channel     │
        └─────────────────┘
```
