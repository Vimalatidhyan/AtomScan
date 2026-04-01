# Automatic Output-to-UI Data Binding System

## Overview

The Automatic Output-to-UI Data Binding System automatically scans the output directory, detects all files (JSON, TXT, CSV, LOG), parses them intelligently, and binds the parsed data directly to the corresponding dashboard UI modules.

**Key Features:**
- ✅ Automatically discovers all files in `output/<scan_name>/`
- ✅ Intelligently routes files to UI modules based on filename patterns
- ✅ No hardcoded file handling or manual configuration needed
- ✅ Supports JSON, TXT, CSV, and LOG formats
- ✅ Dynamically populates module counters and data tables
- ✅ Removes placeholder messages like "Waiting for data..."
- ✅ Every output file is visible somewhere in the dashboard

## Architecture

### Backend Components

#### 1. **Output UI Binder** (`app/api/helpers/output_ui_binder.py`)
Provides the core functionality:
- `UIModuleRouter`: Routes files to modules based on filename patterns
- `UniversalFileParser`: Parses JSON, TXT, CSV, LOG files
- `ScanOutputScanner`: Discovers and scans output directory
- `UIModuleSummarizer`: Creates counters and summaries for UI
- `get_dashboard_output_data()`: Main entry point

#### 2. **API Endpoint** (`app/api/routes/scans.py`)
New endpoint: `GET /api/v1/scans/{scan_id}/output-data`

Returns structured data organized by UI module:
```json
{
  "status": "success",
  "scan_id": 4,
  "domain": "example.com",
  "total_files": 32,
  "module_count": 8,
  "modules": {
    "dns_resolution": {
      "module": "dns_resolution",
      "file_count": 1,
      "status": "has_data",
      "record_count": 6,
      "unique_hostnames": 6,
      "unique_ips": 3,
      "files": [...]
    },
    "asn_ip": {...},
    "certificate_transparency": {...},
    ...
  },
  "unrouted_files": [...]
}
```

### Frontend Components

#### 1. **Output UI Binder Script** (`scripts/web/static/assets/js/output-ui-binder.js`)
Main JavaScript class for consuming and rendering the data:

```javascript
class OutputUIBinder {
  constructor(scanId, apiBase = '/api/v1');
  
  // Fetch output data
  async fetchAndBindOutputData();
  
  // Get module data
  getModuleData(moduleName);
  
  // Update specific module
  updateModule(moduleName, selector, renderer);
  
  // Update all modules
  updateAllModules(renderers);
  
  // Get module summary
  getModuleSummary(moduleName);
}

// Helper function
async initializeAutoOutputBinding(scanId, customRenderers = {})
```

#### 2. **Built-in Renderers**
Pre-built rendering functions for:
- DNS Resolution
- ASN & IP Ranges
- Certificate Transparency
- Cloud Exposure
- Domain Intelligence / WHOIS
- Vulnerabilities
- Subdomains

## File Routing Patterns

Files are automatically routed to modules based on filename patterns:

| Module | File Patterns |
|--------|---------------|
| **domain_intelligence** | `whois.txt`, `prescan_risk_profile.json`, `domain_*.json` |
| **dns_resolution** | `dnsx_resolved.json`, `dns_*.json`, `resolved*.json` |
| **asn_ip** | `asn_*.txt/.json`, `*_ips.txt`, `*_cidrs.txt` |
| **certificate_transparency** | `certspotter.txt`, `ct_*.txt/.json`, `certificate*.txt/.json` |
| **cloud_exposure** | `cloud_*.txt/.json`, `s3*.txt/.json`, `goblob*.txt`, `gcpbucket*.txt` |
| **subdomains** | `subdomains.txt`, `*subdomains*.txt/.json` |
| **active_hosts** | `alive*.txt`, `active*.txt`, `*_hosts.txt` |
| **vulnerabilities** | `cve_*.txt/.json`, `vuln*.txt/.json`, `findings*.txt/.json`, `nikto*.json` |
| **content_discovery** | `ffuf_*.json`, `javascript_*.txt`, `secrets*.txt`, `*_urls.txt` |
| **threat_intel** | `threat*.json`, `osint*.json`, `malware*.txt/.json`, `ioc*.txt/.json` |
| **port_scans** | `nmap.xml`, `ports*.json`, `*port*.json/.xml` |
| **http_security** | `headers*.json`, `ssl*.json`, `security*.json` |

## Integration Steps

### 1. Add Script Reference

Add to your dashboard HTML file:

```html
<head>
  <!-- ... other scripts ... -->
  <script src="/assets/js/output-ui-binder.js"></script>
</head>
```

### 2. Add Data Attributes to Module Elements

Update your module HTML elements with data attributes:

```html
<!-- DNS Resolution Module -->
<div class="module" data-module="dns_resolution">
  <h3>DNS Resolution</h3>
  <div class="module-content">
    <!-- Content will be populated here -->
  </div>
</div>

<!-- ASN & IP Module -->
<div class="module" data-module="asn_ip">
  <h3>ASN & IP Ranges</h3>
  <div class="module-content">
    <!-- Content will be populated here -->
  </div>
</div>

<!-- Certificate Transparency Module -->
<div class="module" data-module="certificate_transparency">
  <h3>Certificate Transparency</h3>
  <div class="module-content">
    <!-- Content will be populated here -->
  </div>
</div>

<!-- ... other modules ... -->
```

### 3. Initialize on Page Load

Add to your page script:

```javascript
// Wait for DOM to load
document.addEventListener('DOMContentLoaded', async () => {
  const scanId = <!-- Extract from URL or data attribute -->;
  
  // Initialize automatic output binding
  const binder = await initializeAutoOutputBinding(scanId);
  
  if (binder) {
    console.log('Output data loaded and bound to UI modules');
  }
});
```

### 4. Example: Scan Detail Page Integration

```html
<div class="scan-detail" data-scan-id="4">
  <h1 id="scan-title">Scan Details</h1>
  
  <div class="modules-grid">
    <!-- DNS Resolution -->
    <div class="module" data-module="dns_resolution">
      <h3>DNS Resolution</h3>
      <div class="module-content"></div>
    </div>
    
    <!-- ASN & IPs -->
    <div class="module" data-module="asn_ip">
      <h3>ASN & IP Ranges</h3>
      <div class="module-content"></div>
    </div>
    
    <!-- Certificate Transparency -->
    <div class="module" data-module="certificate_transparency">
      <h3>Certificate Transparency</h3>
      <div class="module-content"></div>
    </div>
    
    <!-- Cloud Exposure -->
    <div class="module" data-module="cloud_exposure">
      <h3>Cloud Exposure</h3>
      <div class="module-content"></div>
    </div>
    
    <!-- WHOIS / Domain Intelligence -->
    <div class="module" data-module="domain_intelligence">
      <h3>Domain Intelligence</h3>
      <div class="module-content"></div>
    </div>
    
    <!-- Vulnerabilities -->
    <div class="module" data-module="vulnerabilities">
      <h3>Vulnerabilities</h3>
      <div class="module-content"></div>
    </div>
  </div>
</div>

<script src="/assets/js/output-ui-binder.js"></script>
<script>
document.addEventListener('DOMContentLoaded', async () => {
  const container = document.querySelector('.scan-detail');
  const scanId = parseInt(container.dataset.scanId);
  
  // Initialize with built-in renderers
  const binder = await initializeAutoOutputBinding(scanId);
  
  if (!binder) {
    console.error('Failed to initialize output binding');
    return;
  }
  
  // Optional: Custom logic after initialization
  const summary = binder.getModuleSummary('dns_resolution');
  if (summary) {
    console.log(`DNS: ${summary.summary.record_count} records found`);
  }
});
</script>
```

## Custom Renderers

You can create custom renderers for specific modules:

```javascript
const myRenderers = {
  dns_resolution: {
    selector: '#my-dns-module',
    render: function(data, selector) {
      const element = document.querySelector(selector);
      
      // data structure:
      // {
      //   module: "dns_resolution",
      //   file_count: 1,
      //   record_count: 6,
      //   unique_hostnames: 6,
      //   unique_ips: 3,
      //   files: [...]
      // }
      
      let html = `
        <div class="dns-table">
          <p>Found ${data.record_count} DNS records</p>
          <ul>
      `;
      
      data.files.forEach(file => {
        const records = file.data;
        if (Array.isArray(records)) {
          records.forEach(record => {
            html += `<li>${record.host} → ${record.a}</li>`;
          });
        }
      });
      
      html += '</ul></div>';
      element.innerHTML = html;
    }
  }
};

// Use custom renderers
const binder = await initializeAutoOutputBinding(scanId, myRenderers);
```

## File Parsing

### JSON Files
- Parses both single JSON objects and JSONL format (one JSON per line)
- Returns parsed objects or array of objects

### TXT Files
- Splits into lines
- Returns: `{ type: "text", lines: [...], line_count: N, raw_content: "..." }`

### CSV Files
- Parses using standard CSV format
- Returns: `{ type: "csv", rows: [...], row_count: N, columns: [...] }`

### LOG Files
- Same as TXT files
- Returns: `{ type: "text", lines: [...], line_count: N, raw_content: "..." }`

## API Response Structure

```json
{
  "status": "success",
  "scan_id": 4,
  "domain": "example.com",
  "scan_dir": "/path/to/output/example_com_scan_4",
  "total_files": 32,
  "module_count": 8,
  "modules": {
    "module_name": {
      "module": "module_name",
      "file_count": 2,
      "files": [
        {
          "filename": "file.txt",
          "file_type": "txt",
          "file_size": 4096,
          "data": {...},
          "status": "success"
        },
        ...
      ],
      "status": "has_data",
      "should_show_placeholder": false,
      "record_count": 10,
      "unique_items": 5,
      ...
    },
    ...
  },
  "unrouted_files": [
    {
      "filename": "unknown_file.txt",
      "relative_path": "phase1_discovery/unknown_file.txt"
    },
    ...
  ]
}
```

## JavaScript API Reference

### OutputUIBinder Class

#### Constructor
```javascript
const binder = new OutputUIBinder(scanId, apiBase = '/api/v1');
```

#### Methods

**fetchAndBindOutputData()**
```javascript
const result = await binder.fetchAndBindOutputData();
// Returns: { hasData: bool, moduleCount: int, totalFiles: int, modules: {}, ... }
```

**getModuleData(moduleName)**
```javascript
const dnsData = binder.getModuleData('dns_resolution');
// Returns: { module, file_count, files, record_count, ... }
```

**updateModule(moduleName, selector, renderer)**
```javascript
binder.updateModule('dns_resolution', '[data-module="dns"]', 
  function(data, selector) {
    document.querySelector(selector).innerHTML = `<p>${data.record_count} records</p>`;
  }
);
```

**updateAllModules(renderers)**
```javascript
const results = binder.updateAllModules({
  dns_resolution: { selector: '...', render: function(data, sel) {...} },
  asn_ip: { selector: '...', render: function(data, sel) {...} }
});
// Returns: { module_name: true/false, ... }
```

**getModuleSummary(moduleName)**
```javascript
const summary = binder.getModuleSummary('dns_resolution');
// Returns: { module, fileCount, status, files, summary: {...} }
```

**getModuleRawData(moduleName)**
```javascript
const rawFiles = binder.getModuleRawData('dns_resolution');
// Returns: Array of file data objects
```

### Helper Function

**initializeAutoOutputBinding(scanId, customRenderers = {})**
```javascript
const binder = await initializeAutoOutputBinding(scanId, {
  dns_resolution: { ... }
});
// Returns: OutputUIBinder instance
// - Automatically fetches output data
// - Updates all registered modules
// - Logs unbound files
```

## Best Practices

1. **Always check for data before rendering:**
   ```javascript
   const data = binder.getModuleData('dns_resolution');
   if (!data || data.status === 'no_data') {
     // Show placeholder or handle empty state
   }
   ```

2. **Handle parsing errors gracefully:**
   - The system catches parsing errors and returns error data
   - Check `data.status` to detect issues

3. **Cache results if calling multiple times:**
   ```javascript
   const binder = await initializeAutoOutputBinding(scanId);
   // Reuse this instance instead of calling again
   ```

4. **Show file sources:**
   - Always display which files contributed to the data
   - Use `data.files[].filename` to show sources

5. **Update UI dynamically:**
   - Remove "Waiting for data..." messages when data arrives
   - Update counters and statistics

## Error Handling

If the API returns an error:
```javascript
const output = await binder.fetchAndBindOutputData();
if (!output) {
  console.error('Failed to fetch output data');
  // Show error message to user
}
```

If a file fails to parse:
```javascript
const file = data.files[0];
if (file.status === 'parse_error') {
  console.warn(`Parse error in ${file.filename}: ${file.error}`);
}
```

## Debugging

Enable console logging:
```javascript
const binder = new OutputUIBinder(scanId);
const result = await binder.fetchAndBindOutputData();
console.log('Output data:', result);
console.log('Module data:', binder.moduleData);
console.log('Unbound files:', binder.unboundFiles);
```

## Examples

### Example 1: Simple Summary Display
```javascript
async function displayScanSummary(scanId) {
  const binder = await initializeAutoOutputBinding(scanId);
  
  const dns = binder.getModuleSummary('dns_resolution');
  const asn = binder.getModuleSummary('asn_ip');
  const certs = binder.getModuleSummary('certificate_transparency');
  
  document.getElementById('summary').innerHTML = `
    <ul>
      <li>DNS Records: ${dns?.summary?.record_count || 0}</li>
      <li>IPs Found: ${asn?.summary?.ip_count || 0}</li>
      <li>Certificates: ${certs?.summary?.certificate_count || 0}</li>
    </ul>
  `;
}
```

### Example 2: Export Data
```javascript
async function exportScanData(scanId) {
  const binder = await initializeAutoOutputBinding(scanId);
  
  const allModules = binder.moduleData;
  const json = JSON.stringify(allModules, null, 2);
  downloadFile(json, 'scan-data.json');
}
```

### Example 3: Dynamic Module List
```javascript
async function listAvailableModules(scanId) {
  const binder = await initializeAutoOutputBinding(scanId);
  
  const modules = Object.keys(binder.moduleData).map(name => {
    const data = binder.moduleData[name];
    return {
      name,
      fileCount: data.file_count,
      hasData: data.status === 'has_data'
    };
  });
  
  return modules;
}
```

## Supported Modules

All automatically detected modules:
- ✅ domain_intelligence
- ✅ dns_resolution  
- ✅ asn_ip
- ✅ certificate_transparency
- ✅ cloud_exposure
- ✅ subdomains
- ✅ active_hosts
- ✅ vulnerabilities
- ✅ content_discovery
- ✅ threat_intel
- ✅ port_scans
- ✅ http_security

## Troubleshooting

### Files not being routed
- Check file names match the patterns in `ROUTE_PATTERNS`
- Add custom routing by extending `UIModuleRouter`
- Check console for unrouted files list

### Data not appearing
- Verify the output directory contains files
- Check API endpoint returns status 200
- Look for parse errors in file.status field

### Custom renderer not called
- Ensure module name matches exactly
- Verify selector matches your HTML elements
- Check browser console for errors

## Future Enhancements

Potential additions:
- Custom file type parsers
- Real-time file watching and updates
- Caching layer for performance
- Batch file operations
- Export functionality
- Module filtering and search
