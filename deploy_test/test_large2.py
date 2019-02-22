
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

	for x in range(256):
		dat = ob.datas.add()
		dat.dataType = 10
		dat.data = "/dev/null"

	payload = report.SerializeToString()
	r = common.test_send( payload )
	if r != 200: raise Exception("test1 result")


if __name__ == "__main__":
	test1()
