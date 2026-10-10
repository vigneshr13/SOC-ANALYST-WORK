# Grafana SOC Metrics Dashboard

## Overview

Operational dashboard pulling live data from Wazuh and Splunk to track SOC performance KPIs.

## Dashboard Panels

### 1. Alert Volume by Severity (Line Chart)
- **Data Source:** Wazuh alerts index
- **Query:** Aggregated alert count by severity level (Critical, High, Medium, Low) over time
- **Time Range:** Last 30 days, 1-day buckets
- **Purpose:** Trend analysis — are alerts increasing? Which severity is dominant?

### 2. MTTA Tracking (Gauge + Trend)
- **Data Source:** TheHive case metadata
- **Metric:** Mean Time to Acknowledge = (case acknowledged timestamp) - (alert created timestamp)
- **Target:** ≤ 15 minutes (KPI threshold)
- **Display:** Gauge showing current MTTA with green/amber/red zones + trend line

### 3. False Positive Rate (Line Chart)
- **Data Source:** TheHive case outcomes
- **Metric:** (Cases closed as false positive) / (Total cases) * 100
- **Target:** < 5% (displayed as reference line)
- **Purpose:** Track detection tuning effectiveness over time

### 4. Top 10 Triggered Detection Rules (Bar Chart)
- **Data Source:** Wazuh rule triggers
- **Query:** Count of alerts grouped by rule ID and description, top 10
- **Purpose:** Identify noisiest rules for tuning priority

### 5. Top Attacker IPs / Targeted Assets (Table)
- **Data Source:** Wazuh alerts + Splunk correlation
- **Columns:** Source IP | Country | Total Alerts | Targeted Assets | Last Seen
- **Purpose:** Situational awareness — who is targeting what

## Setup Instructions

1. Install Grafana: `sudo apt install -y grafana`
2. Configure Elasticsearch data source (Wazuh indexer)
3. Configure Splunk data source (via Grafana Splunk plugin)
4. Import `dashboard_export.json` via Grafana UI (Dashboards > Import)
5. Verify data source connectivity and adjust time ranges

## Files

- `dashboard_export.json` — Importable Grafana dashboard (JSON model)
- `screenshots/` — Dashboard screenshots for portfolio documentation
