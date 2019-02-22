
import addsec_cti_pb2
import common
import time

def test1():
	report = addsec_cti_pb2.Report()
	common.test_populate( report )

	ob = report.observations.add()
	ob.observationType = 2
	ob.timestamp = int(time.time())
	ob.testId = 50

	dat = ob.datas.add()
	dat.dataType = 10
	dat.data = "A" * 8192

	payload = report.SerializeToString()
	r = common.test_send( payload )
	if r != 200: raise Exception("test1 result")

def test2():
	report = addsec_cti_pb2.Report()
	common.test_populate( report )

	ob = report.observations.add()
	ob.observationType = 2
	ob.timestamp = int(time.time())
	ob.testId = 50

	dat = ob.datas.add()
	dat.dataType = 10
	dat.data = "/dev/null"

	report.organizationId = "A" * 8192

	payload = report.SerializeToString()
	r = common.test_send( payload )
	if r != 200: raise Exception("test1 result")

def test3():
	report = addsec_cti_pb2.Report()
	common.test_populate( report )

	ob = report.observations.add()
	ob.observationType = 2
	ob.timestamp = int(time.time())
	ob.testId = 50

	dat = ob.datas.add()
	dat.dataType = 10
	dat.data = "/dev/null"

	report.systemId = "A" * 8192

	payload = report.SerializeToString()
	r = common.test_send( payload )
	if r != 200: raise Exception("test1 result")

def test4():
	report = addsec_cti_pb2.Report()
	common.test_populate( report )

	ob = report.observations.add()
	ob.observationType = 2
	ob.timestamp = int(time.time())
	ob.testId = 50

	dat = ob.datas.add()
	dat.dataType = 10
	dat.data = "/dev/null"

	report.applicationId = "A" * 8192

	payload = report.SerializeToString()
	r = common.test_send( payload )
	if r != 200: raise Exception("test1 result")


if __name__ == "__main__":
	try: test1()
	except: pass

	try: test2()
	except: pass

	try: test3()
	except: pass

	try: test4()
	except: pass
