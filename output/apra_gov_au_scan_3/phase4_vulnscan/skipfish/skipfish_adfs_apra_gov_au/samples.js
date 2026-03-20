var mime_samples = [
  { 'mime': 'text/html', 'samples': [
    { 'url': 'https://adfs.apra.gov.au/public/', 'dir': '_m0/0', 'linked': 2, 'len': 3480 } ]
  },
  { 'mime': 'text/plain', 'samples': [
    { 'url': 'https://adfs.apra.gov.au/vdesk/', 'dir': '_m1/0', 'linked': 1, 'len': 86 } ]
  }
];

var issue_samples = [
  { 'severity': 4, 'type': 50102, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/vdesk/`false`', 'extra': 'responses to `true` and `false` different than to `uname`', 'sid': '0', 'dir': '_i0/0' } ]
  },
  { 'severity': 1, 'type': 20203, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/vdesk/?_test1=c:\x5cwindows\x5csystem32\x5ccmd.exe&_test2=/etc/passwd&_test3=|/bin/sh&_test4=(SELECT%20*%20FROM%20nonexistent)%20--&_test5=\x3e/no/such/file&_test6=\x3cscript\x3ealert(1)\x3c/script\x3e&_test7=javascript:alert(1)', 'extra': '', 'sid': '0', 'dir': '_i1/0' } ]
  },
  { 'severity': 1, 'type': 20102, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/public/', 'extra': 'Too many previous fetch failures', 'sid': '0', 'dir': '_i2/0' },
    { 'url': 'https://adfs.apra.gov.au/public/images/', 'extra': 'Too many previous fetch failures', 'sid': '0', 'dir': '_i2/1' },
    { 'url': 'https://adfs.apra.gov.au/public/images/customization/Common/PRD_External_ADFS.app/PRD_External_ADFS_general_ui/logo_image_en.png', 'extra': 'Child node limit exceeded', 'sid': '0', 'dir': '_i2/2' },
    { 'url': 'https://adfs.apra.gov.au/public/images/customization/', 'extra': 'Too many previous fetch failures', 'sid': '0', 'dir': '_i2/3' },
    { 'url': 'https://adfs.apra.gov.au/public/include/', 'extra': 'Too many previous fetch failures', 'sid': '0', 'dir': '_i2/4' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/weekly.app', 'extra': 'Too many previous fetch failures', 'sid': '0', 'dir': '_i2/5' } ]
  },
  { 'severity': 1, 'type': 20101, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/FOO-sfi9876', 'extra': 'PUT upload', 'sid': '0', 'dir': '_i3/0' },
    { 'url': 'https://adfs.apra.gov.au/public/sfi9876.php3', 'extra': 'during 404 response checks', 'sid': '0', 'dir': '_i3/1' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/sfi9876.bak', 'extra': 'during 404 response checks', 'sid': '0', 'dir': '_i3/2' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/uds.err', 'extra': 'during path-based dictionary probes', 'sid': '0', 'dir': '_i3/3' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/c_ses.php3', 'extra': 'during initial file fetch', 'sid': '0', 'dir': '_i3/4' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/c_ses.php3?orig_uri=9876sfi', 'extra': 'param behavior', 'sid': '0', 'dir': '_i3/5' },
    { 'url': 'https://adfs.apra.gov.au/my.policy', 'extra': 'during initial resource fetch', 'sid': '0', 'dir': '_i3/6' } ]
  },
  { 'severity': 0, 'type': 10901, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/vdesk/c_ses.php3', 'extra': '', 'sid': '0', 'dir': '_i4/0' } ]
  },
  { 'severity': 0, 'type': 10801, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/vdesk/', 'extra': 'text/plain', 'sid': '0', 'dir': '_i5/0' } ]
  },
  { 'severity': 0, 'type': 10205, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/0' },
    { 'url': 'https://adfs.apra.gov.au/sfi9876.php3', 'extra': '', 'sid': '0', 'dir': '_i6/1' },
    { 'url': 'https://adfs.apra.gov.au/public/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/2' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/3' } ]
  },
  { 'severity': 0, 'type': 10204, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/public/', 'extra': 'X-Frame-Options', 'sid': '0', 'dir': '_i7/0' },
    { 'url': 'https://adfs.apra.gov.au/public/', 'extra': 'X-XSS-Protection', 'sid': '0', 'dir': '_i7/1' },
    { 'url': 'https://adfs.apra.gov.au/public/', 'extra': 'X-Content-Type-Options', 'sid': '0', 'dir': '_i7/2' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/', 'extra': 'X-Frame-Options', 'sid': '0', 'dir': '_i7/3' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/', 'extra': 'X-XSS-Protection', 'sid': '0', 'dir': '_i7/4' },
    { 'url': 'https://adfs.apra.gov.au/vdesk/', 'extra': 'X-Content-Type-Options', 'sid': '0', 'dir': '_i7/5' } ]
  },
  { 'severity': 0, 'type': 10202, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/', 'extra': 'BigIP', 'sid': '0', 'dir': '_i8/0' } ]
  },
  { 'severity': 0, 'type': 10201, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/', 'extra': 'LastMRH_Session', 'sid': '0', 'dir': '_i9/0' },
    { 'url': 'https://adfs.apra.gov.au/', 'extra': 'MRHSession', 'sid': '0', 'dir': '_i9/1' },
    { 'url': 'https://adfs.apra.gov.au/', 'extra': 'MRHSHint', 'sid': '0', 'dir': '_i9/2' } ]
  },
  { 'severity': 0, 'type': 10101, 'samples': [
    { 'url': 'https://adfs.apra.gov.au/', 'extra': '/C=US/O=DigiCert Inc/CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1', 'sid': '0', 'dir': '_i10/0' } ]
  }
];

