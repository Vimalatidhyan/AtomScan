import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.api.routes.subdomain_lookup import (
    CertMonitorResponse, CertRecord, _cert_status, _query_crtsh_full
)

status_tests = [
    _cert_status("2025-01-01"),        # expired
    _cert_status("2026-02-28"),        # expiring soon (within 30 days of Feb 24 2026)
    _cert_status("2026-12-31"),        # valid
    _cert_status(None),                # None -> valid
]
print("cert_status tests:", status_tests)
print("All imports OK")
