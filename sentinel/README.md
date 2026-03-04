# Sentinel Analytic Rules

Detection-as-code for Microsoft Sentinel. Each YAML file is a standalone analytic rule with a KQL query, MITRE ATT&CK mapping, severity, and entity mappings — ready to deploy to a Sentinel workspace.

## Prerequisites

1. **Log Analytics workspace** with Igel events ingested into a custom table named `Igel_CL`.
2. **Data Collection Rule (DCR)** that routes Igel NDJSON events from Azure IoT Hub (or any ingestion path) into the workspace.
3. **Microsoft Sentinel** enabled on the workspace.

### Table schema

Igel's NDJSON envelope maps to Log Analytics columns:

| Column | Type | Source |
|---|---|---|
| `TimeGenerated` | datetime | `ts` |
| `device` | string | `device` |
| `kind` | string | `kind` |
| `v` | string | `v` |
| *(payload fields)* | *(varies)* | Flattened from each event type |

Use a DCR transformation to parse the NDJSON and map `ts` → `TimeGenerated`. All other fields are ingested as-is.

## Rules

| File | MITRE | Severity | Signal |
|---|---|---|---|
| `unexpected-script-interpreter.yaml` | T1059 | High | Script interpreter running on headless device |
| `new-listening-service.yaml` | T1021, T1090 | High | Unauthorized listening socket on well-known port |
| `outbound-connection-anomaly.yaml` | T1071, T1571, T1095 | Medium | Outbound connection to non-standard port |
| `fim-critical-file-modified.yaml` | T1098, T1565.001 | High | Modification of passwd, shadow, sshd_config |
| `fim-persistence-implant.yaml` | T1547, T1574 | High | Change in autostart, init, or library preload paths |
| `baseline-ssh-hardening-drift.yaml` | T1556 | High | SSH config weakened (root login, empty passwords) |
| `baseline-defense-degradation.yaml` | T1548, T1562 | Medium | ASLR, SYN cookies, or mount options degraded |
| `baseline-credential-exposure.yaml` | T1552 | High | Credential file permissions too permissive |
| `tamper-process-injection.yaml` | T1055 | Critical | Active ptrace injection detected |
| `tamper-kernel-integrity.yaml` | T1014 | Critical | Kernel taint flag non-zero |
| `tamper-unauthorized-rw-mount.yaml` | T1006 | Critical | Critical path mounted read-write |
| `missing-heartbeat.yaml` | T1562.001 | Medium | Device stopped sending heartbeats |
| `resource-hijacking.yaml` | T1496 | Medium | Sustained high CPU or memory usage |

## Deploy

### Azure CLI

```sh
# Import a single rule
az sentinel alert-rule create \
  --resource-group <rg> \
  --workspace-name <workspace> \
  --alert-rule-id $(uuidgen) \
  --scheduled \
  --template @sentinel/tamper-process-injection.yaml

# Import all rules
for f in sentinel/*.yaml; do
  az sentinel alert-rule create \
    --resource-group <rg> \
    --workspace-name <workspace> \
    --alert-rule-id $(uuidgen) \
    --scheduled \
    --template @"$f"
done
```

### Sentinel Repositories (CI/CD)

Connect this Git repo as a [Sentinel Repository](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd) and point the content path to `sentinel/`. Rules will be deployed and updated automatically on push.

### Manual import

In the Azure portal: **Sentinel → Analytics → Import** and select any YAML file.

## Customization

- **`allowed_ports`** in `outbound-connection-anomaly.yaml` — add ports your devices legitimately connect to.
- **`suspicious_ports`** in `new-listening-service.yaml` — adjust to match your device profile.
- **`heartbeat_threshold`** in `missing-heartbeat.yaml` — set to match your `heartbeat_interval` config plus a tolerance margin.
- **`cpu_threshold` / `mem_threshold`** in `resource-hijacking.yaml` — tune per device class.
- **Table name** — if your DCR maps to a different table name, find-and-replace `Igel_CL` across all files.
