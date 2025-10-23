# Uncontrolled Recursion in JSON/XML Parsing Leading to Denial of Service

## Summary

ezBookkeeping versions 1.2.0 and earlier contain a critical vulnerability in JSON and XML file import processing. The application fails to validate nesting depth during parsing operations, allowing authenticated attackers to trigger denial of service conditions by uploading deeply nested malicious files. This results in CPU exhaustion, service degradation, or complete service unavailability.

**Confirmed Vulnerable Components**:
- JSON import module (`pkg/converters/default/`)
- GnuCash XML import (`pkg/converters/gnucash/`)
- OFX/QFX XML import (`pkg/converters/ofx/`)
- CAMT.053 XML import (`pkg/converters/camt/`)

## Vulnerability Details

### CVE Classification

- **CWE ID**: [CWE-674](https://cwe.mitre.org/data/definitions/674.html) - Uncontrolled Recursion
- **CVSS 3.1 Score**: **7.5** (High)
- **CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

| Metric | Value | Explanation |
|--------|-------|-------------|
| Attack Vector (AV) | Network (N) | Exploitable remotely over the network |
| Attack Complexity (AC) | Low (L) | No special conditions required |
| Privileges Required (PR) | Low (L) | Requires authenticated user account |
| User Interaction (UI) | None (N) | No user interaction needed |
| Scope (S) | Unchanged (U) | Vulnerability affects only the vulnerable component |
| Confidentiality (C) | None (N) | No data disclosure |
| Integrity (I) | None (N) | No data modification |
| Availability (A) | High (H) | Complete service unavailability |

### Technical Description

ezBookkeeping utilizes Go's standard library packages `encoding/json` and `encoding/xml` for data parsing. These packages, in their default configuration, **do not enforce recursion depth limits**. When processing deeply nested data structures, this leads to:

1. **Stack Exhaustion**: Deep recursive calls consume excessive stack memory
2. **CPU Resource Saturation**: Parser must traverse every nesting level
3. **Exponential Response Time**: Parsing time increases exponentially with depth

**Vulnerable Code Paths**:

```go
// pkg/converters/default/default_transaction_data_json_file_importer.go:41
func (c *defaultTransactionDataJsonImporter) ParseImportedData(...) {
    var importRequest models.ImportTransactionRequest

    // ❌ No depth validation before parsing
    if err := json.Unmarshal(data, &importRequest); err != nil {
        return nil, nil, nil, nil, nil, nil, errs.ErrInvalidJSONFile
    }
    // ...
}
```

```go
// pkg/converters/gnucash/gnucash_data_reader.go:23
func (r *gnucashDatabaseReader) read(ctx core.Context) (*gnucashDatabase, error) {
    database := &gnucashDatabase{}

    // ❌ No depth validation before parsing
    err := r.xmlDecoder.Decode(&database)
    // ...
}
```
---

## Proof of Concept

### Attack Vector: Deep-Nested GnuCash XML (Verified)

**Test Environment**:
- Docker container with resource limits: 1 CPU core, 512MB RAM
- Target: ezBookkeeping v1.2.0
- Endpoint: `http://localhost:3020`

**Attack Command**:
```bash
# Generate 10,000-level nested XML payload (~40KB per file)
python3 generate_deep_json.py

# Launch concurrent attack with 10 malicious files
for i in {1..10}; do
  curl -X POST http://localhost:3020/api/v1/transactions/parse_import.json \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Timezone-Offset: 0" \
    -F "fileType=gnucash" \
    -F "file=@deep_xml_critical_10000.xml" &
done
```

**Observed Results**:
- Container Crash
- Or CPU usage 100% and RAM usage 100%

### 300 Requests with 1000 layer xml (Cause 100% Performance Usage)
<img width="617" height="120" alt="image" src="https://github.com/user-attachments/assets/dbafa761-ae91-4038-ab73-81f7729206f7" />

### 10 Requests with 5000 layer xml (Cause Crash immediately)
<img width="1097" height="413" alt="image" src="https://github.com/user-attachments/assets/00cadd17-6f2d-48f1-9cfc-e02247dccc2d" />


**Impact Metrics**:
  - Total Bandwidth: 400 KB (10 × 40 KB files)
  - Attack Cost: **Extremely Low** (small file sizes)
  - Scope: **Complete Service Disruption**
  - Recovery: **Manual Container Restart Required**

## Impact Assessment

### Exploitability

- ✅ **Remotely Exploitable**: Via HTTP API file upload
- ✅ **Low Technical Barrier**: Single-line Python script generates payload
- ✅ **Bypasses Size Limits**: 10,000 nesting levels = only 20-40KB
- ⚠️ **Authentication Required**: Attacker needs valid user account

### Impact Scope

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Service Availability** | 🔴 Critical | Complete service unresponsiveness or crash |
| **User Experience** | 🔴 Critical | Legitimate users cannot access service |
| **Resource Consumption** | 🟡 Moderate | CPU 100%, elevated memory usage |
| **Data Integrity** | 🟢 Low | No data corruption or leakage risk |


---

## Remediation

### Immediate Mitigations

#### 1. Enforce Request Timeouts

```go
// cmd/webserver.go
srv := &http.Server{
    Addr:              ":8080",
    Handler:           router,
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    ReadHeaderTimeout: 5 * time.Second,
}
```

#### 2. Configure WAF/Reverse Proxy Rules

For Nginx deployments:
```nginx
client_max_body_size 5M;
proxy_connect_timeout 10s;
proxy_send_timeout 10s;
proxy_read_timeout 10s;
```

#### 3. Enable Rate Limiting

```ini
# config.ini
max_import_requests_per_hour = 10
```
