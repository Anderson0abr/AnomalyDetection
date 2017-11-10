from scapy.all import *
from time import sleep

class Test():
	def __init__():
		pass

	def test():
		print("Sending packages...")
		#srcs=["www.github.com", "www.facebook.com", "www.google.com", "www.gmail.com", "www.9gag.com"]
		srcs=["192.30.253.112", "157.24.12.35", "172.217.29.164", "216.58.202.229", "151.101.66.133"]
		dest="10.10.10.10"

		for i in range(5):
			send(IP(src=srcs[0], dst=dest)/TCP())
		send(IP(src=srcs[4], dst=dest)/TCP())
		sleep(10)
		for i in range(4):
			send(IP(src=srcs[1], dst=dest)/TCP())
			send(IP(src=srcs[2], dst=dest)/TCP())
			send(IP(src=srcs[3], dst=dest)/TCP())
		send(IP(src=srcs[0], dst=dest)/TCP())
		sleep(10)
		send(IP(src=srcs[0], dst=dest)/TCP())