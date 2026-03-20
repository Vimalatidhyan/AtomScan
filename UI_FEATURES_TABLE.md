# Scan Viewer v2 - UI Features & Options

## 📋 Complete Feature Inventory

### 🧭 SIDEBAR NAVIGATION

| Section | Menu Item | Icon | Function |
|---------|-----------|------|----------|
| **Main** | Dashboard | Grid | Navigate to main dashboard |
| **Main** | Attack Surface | Globe | View attack surface |
| **Security** | Assessments | Play Icon | View security assessments (ACTIVE) |
| **Security** | Vulnerabilities | Shield | View identified vulnerabilities |
| **Security** | Threat Intel | Radar | View threat intelligence |
| **Discovery** | Subdomain Finder | Search | Find subdomains |
| **Analysis** | Attack Graph | Node Graph | View attack graph visualization |
| **Analysis** | Reports | Document | View security reports |
| **Analysis** | Compliance | Checkmark | View compliance status |
| **System** | Alerts | Bell | View system alerts |
| **System** | Settings | Gear | Access settings |

---

### 📊 TOP BAR CONTROLS

| Control | Type | Function |
|---------|------|----------|
| Sidebar Toggle | Button | Toggle sidebar visibility |
| Page Title | Text | Shows "Assessments" |
| Breadcrumb | Navigation | Security › Assessments |
| New Assessment | Primary Button | Create new security assessment |
| Notification Bell | Icon Button | Show notifications |
| Notification Badge | Badge | Display notification count |

---

### 📑 TAB FILTERS

| Tab Name | Display | Purpose |
|----------|---------|---------|
| All | Total count | Show all assessments |
| Running | Count | Show active/running assessments |
| Completed | Count | Show finished assessments |
| Failed | Count | Show failed assessments |

---

### 🔍 SEARCH & FILTER

| Element | Type | Function |
|---------|------|----------|
| Search Box | Input Field | Search assessments by target domain |
| Search Icon | Visual | Indicates search functionality |
| Placeholder | Text | "Search by target..." |

---

### 📋 ASSESSMENT TABLE COLUMNS

| Column | Data Type | Purpose |
|--------|-----------|---------|
| Name | Text | Assessment name |
| Target | Domain | Target domain for scan |
| Phases | Tags | Scan phases (1,2,3,4) |
| Status | Badge | Current status (Running/Completed/Failed) |
| Started | Timestamp | When assessment started |
| Progress | Percentage | Completion percentage |
| Actions | Buttons | View/Edit/Delete/Retry actions |

---

### 📈 DETAIL PANEL - KEY STATISTICS

| Statistic | Display | Purpose |
|-----------|---------|---------|
| Subdomains | Number | Total subdomains discovered |
| Live Hosts | Number | Number of active hosts |
| Open Ports | Number | Total open ports found |
| Vulnerabilities | Number | Total vulnerability count |
| Critical | Number | Critical severity count |
| Cloud Assets | Number | Cloud resources discovered |

---

### 🎯 COLLAPSIBLE DATA PANELS

#### 1. **Live Hosts Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | TXT, JSON |
| Host Count Badge | Display | Shows total |
| Host Grid Display | List | IP addresses in monospace font |
| Export TXT | Button | Export as plain text |
| Export JSON | Button | Export as JSON |

#### 2. **ASN & IP Ranges Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | TXT, JSON |
| CIDR Count Badge | Display | Shows total ranges |
| CIDR Tag Display | Tags | Colored tags with CIDR notation |
| Export TXT | Button | Export as plain text |
| Export JSON | Button | Export as JSON |

#### 3. **Domain Intelligence Panel (WHOIS Data)**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | JSON |
| WHOIS Badge | Display | Shows records count |
| WHOIS Details | Formatted | Domain registration details |
| Export JSON | Button | Export as JSON |

#### 4. **DNS Resolution Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | CSV |
| DNS Count Badge | Display | Shows total records |
| DNS Table | Table | Domain → IP mapping table |
| Export CSV | Button | Export as CSV |

#### 5. **Cloud Exposure Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | JSON, CSV |
| Cloud Count Badge | Display | Shows total assets |
| Cloud Vendor Grid | Grid | AWS, Azure, GCP grouped |
| Vendor Coloring | Visual | Vendor-specific colors |
| Export JSON | Button | Export as JSON |
| Export CSV | Button | Export as CSV |

#### 6. **Certificate Transparency Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | JSON |
| CT Count Badge | Display | Shows total certificates |
| Certificate List | Scrollable | Certificate records |
| Export JSON | Button | Export as JSON |

#### 7. **Scan Details Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | CSV, JSON |
| Asset Count Badge | Display | Shows total assets |
| Assets Table | Table | Discovered assets with details |
| Export CSV | Button | Export as CSV |
| Export JSON | Button | Export as JSON |

#### 8. **Live Scan Logs Panel**
| Feature | Type | Export Options |
|---------|------|-----------------|
| Toggle Collapse | Clickable Header | TXT |
| Log Stream | Live Display | Real-time scan logs |
| Export Logs | Button | Export as TXT |
| Clear Logs | Button | Clear log display |

---

### 🔧 PHASE PROGRESS DISPLAY

| Element | Purpose |
|---------|---------|
| Phase Steps | Visual progress through scan phases |
| Progress Bar | Overall completion percentage |
| Status Indicator | Current phase status |

---

### 🎛️ WORKER JOB STATUS

| Feature | Purpose |
|---------|---------|
| Job Status Panel | Display worker job status |
| Real-time Updates | Live status updates |

---

### 💾 EXPORT CAPABILITIES

| Data Type | Export Formats | Available From |
|-----------|-----------------|-----------------|
| Live Hosts | TXT, JSON | Live Hosts Panel |
| ASN/CIDR | TXT, JSON | ASN & IP Ranges Panel |
| Domain Info | JSON | Domain Intelligence Panel |
| DNS Records | CSV | DNS Resolution Panel |
| Cloud Assets | JSON, CSV | Cloud Exposure Panel |
| Certificates | JSON | Certificate Transparency Panel |
| Scan Details | CSV, JSON | Scan Details Panel |
| Logs | TXT | Live Scan Logs Panel |

---

### 🗂️ MODALS & DIALOGS

#### New Assessment Modal
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| Target Domain | Text Input | Yes | e.g., example.com |
| Scan Phases | Text Input | No | Comma-separated: 1,2,3,4 |
| Submit Button | Primary Button | - | Start Assessment |
| Cancel Button | Secondary Button | - | Close modal |

#### Certificate Transparency Details Modal
| Feature | Type | Purpose |
|---------|------|---------|
| Full-size Modal | Dialog | Display detailed CT records |
| Certificate List | Scrollable | List all certificates |
| Close Button | Action | Dismiss modal |

---

### 📱 RESPONSIVE FEATURES

| Feature | Behavior |
|---------|----------|
| Sidebar Toggle | Hide/show on mobile |
| Table Overflow | Horizontal scroll on small screens |
| Grid Layouts | Auto-fit columns based on width |

---

### 👤 USER INFORMATION

| Element | Display |
|---------|---------|
| Avatar | User initials "AD" |
| Username | "Admin" |
| Role | "Security Analyst" |
| Sidebar Footer | User profile section |

---

### 🎨 STYLING & THEMES

| Element | Style |
|---------|-------|
| Primary Color | Orange (#FF8C00) |
| Gradient | Orange to Red (#FFD84D → #FF8C00 → #FF2D00) |
| Font | Inter (UI), JetBrains Mono (code) |
| Background | Dark theme with glassmorphism |
| Panels | Transparent with blur effect |
| Badges | Color-coded by vendor/status |

---

### ⚙️ TECHNICAL DETAILS

| Component | Script | Version |
|-----------|--------|---------|
| Common Utilities | common.js | v4.0 |
| Output UI Binder | output-ui-binder.js | v1.0 |
| Scan Monitor | scan_monitor_v2.js | v2.1 |
| CSS Stylesheet | style.css | v4.0 |
| Fonts | Google Fonts | Latest |

---

### 📊 PAGINATION

| Feature | Display |
|---------|---------|
| Info Text | "Showing X assessments" |
| Pagination Controls | Previous/Next buttons |
| Dynamic Updates | Updates based on filters |

---

## 🚀 KEY WORKFLOWS

### Workflow 1: View Assessment Details
1. Click assessment row in table
2. Opens detail panel with tabs/phases
3. View statistics
4. Expand individual data panels
5. Export data as needed

### Workflow 2: Create New Assessment
1. Click "New Assessment" button
2. Fill target domain
3. Configure phases (optional)
4. Click "Start Assessment"
5. Monitor progress in table and logs

### Workflow 3: Export Data
1. Open detail panel
2. Click export button (TXT/JSON/CSV)
3. File downloaded
4. Repeat for other panels as needed

### Workflow 4: Monitor Live Scan
1. Select running assessment
2. View phase progress
3. Watch live logs
4. See real-time statistics updates

---

## 🔗 INTEGRATED TOOLS & MODULES

| Tool/Module | Purpose | Integration |
|-------------|---------|-------------|
| DNS Resolution | Domain name resolution | DNS Panel |
| WHOIS Lookup | Domain registration info | Domain Intelligence Panel |
| ASN Lookup | IP range discovery | ASN & IP Ranges Panel |
| Cloud Enumeration | Cloud asset detection | Cloud Exposure Panel |
| Certificate API | SSL/TLS certificate tracking | Certificate Transparency Panel |
| Port Scanner | Open port detection | Scan Details Panel |
| Host Discovery | Live host detection | Live Hosts Panel |
| Vulnerability Scanner | Vuln identification | Vulnerabilities section |

---

## ✅ STATUS INDICATORS

| Status | Meaning |
|--------|---------|
| Running | Scan in progress |
| Completed | Scan finished successfully |
| Failed | Scan encountered errors |
| All | No filter applied |

---

