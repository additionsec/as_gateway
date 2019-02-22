
import addsec_cti_pb2
import common
import time

def test1():
	for x in range(256):
		payload = chr(0) * x
		try: common.test_send( payload )
		except: pass

	for x in range(256):
		payload = chr(x) * 256
		try: common.test_send( payload )
		except: pass


if __name__ == "__main__":
	test1()
