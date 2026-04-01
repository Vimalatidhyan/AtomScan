#!/bin/bash
################################################################################
# Technieum Quick Start Example
# Demonstrates basic usage of Technieum
################################################################################

echo "Technieum Quick Start Examples"
echo "============================"
echo ""

# Example 1: Basic single target scan
echo "Example 1: Basic Scan"
echo "---------------------"
echo "Command: python3 technieum.py -t example.com"
echo "Description: Runs all 4 phases on example.com"
echo ""

# Example 2: Phase-specific scan
echo "Example 2: Discovery Only"
echo "-------------------------"
echo "Command: python3 technieum.py -t example.com -p 1"
echo "Description: Run only Phase 1 (subdomain discovery)"
echo ""

# Example 3: Multiple targets
echo "Example 3: Multiple Targets"
echo "---------------------------"
echo "Command: python3 technieum.py -t example.com,example.org -T 2"
echo "Description: Scan two targets concurrently"
echo ""

# Example 4: Using a targets file
echo "Example 4: From File"
echo "--------------------"
cat > targets_example.txt << 'EOF'
example.com
example.org
example.net
EOF
echo "Created: targets_example.txt"
echo "Command: python3 technieum.py -f targets_example.txt"
echo "Description: Scan all targets from file"
echo ""

# Example 5: Query results
echo "Example 5: Query Results"
echo "------------------------"
echo "Command: python3 query.py -t example.com --summary"
echo "Description: Show summary of scan results"
echo ""
echo "Command: python3 query.py -t example.com --subdomains --alive-only"
echo "Description: Show only alive subdomains"
echo ""
echo "Command: python3 query.py -t example.com --vulns --severity critical"
echo "Description: Show only critical vulnerabilities"
echo ""

# Example 6: Direct database queries
echo "Example 6: Database Queries"
echo "---------------------------"
cat << 'EOF'
# Get all alive subdomains
sqlite3 technieum.db "SELECT host FROM subdomains WHERE target='example.com' AND is_alive=1"

# Count vulnerabilities by severity
sqlite3 technieum.db "SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE target='example.com' GROUP BY severity"

# Find all critical issues
sqlite3 technieum.db "SELECT tool, name, host FROM vulnerabilities WHERE target='example.com' AND severity='critical'"
EOF
echo ""

echo "Full Documentation: See README.md"
echo "For help: python3 technieum.py -h"
