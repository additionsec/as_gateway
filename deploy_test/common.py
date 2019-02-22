
import urllib2
import config

import ssl
if hasattr(ssl, '_create_unverified_context'):
	ssl._create_default_https_context = ssl._create_unverified_context

def test_send( payload ):
	req = urllib2.Request(config.MSG_URI, payload)
	req.add_header('Content-Type','application/octet-stream')
	f = urllib2.urlopen(req)
	return f.getcode()

def test_populate( report ):
	report.organizationId = "bb54cfac59e73d9dae01b84bd476bbadde7d8747".decode('hex')
	report.systemId = "bb54cfac59e73d9dae01b84bd476bbadde7d8747".decode('hex')
	report.applicationId = "com.additionsecurity.deploytest"
