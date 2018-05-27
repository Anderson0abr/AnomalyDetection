#!/usr/bin/python

"""
This example creates a multi-controller network from
semi-scratch; note a topo object could also be used and
would be passed into the Mininet() constructor.
"""

import xml.etree.ElementTree as ET
import re

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller  
from mininet.node import RemoteController
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.cli import CLI
from mininet.log import lg
from mininet.node import Node

#################################
def startNAT( root, inetIntf='eth0', subnet='10.0/8' ):
    """Start NAT/forwarding between Mininet and external network
    root: node to access iptables from
    inetIntf: interface for internet access
    subnet: Mininet subnet (default 10.0/8)="""

    # Identify the interface connecting to the mininet network
    localIntf =  root.defaultIntf()

    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Create default entries for unmatched traffic
    root.cmd( 'iptables -P INPUT ACCEPT' )
    root.cmd( 'iptables -P OUTPUT ACCEPT' )
    root.cmd( 'iptables -P FORWARD DROP' )

    # Configure NAT
    root.cmd( 'iptables -I FORWARD -i', localIntf, '-d', subnet, '-j DROP' )
    root.cmd( 'iptables -A FORWARD -i', localIntf, '-s', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -t nat -A POSTROUTING -o ', inetIntf, '-j MASQUERADE' )

    # Instruct the kernel to perform forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=1' )

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""
    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Instruct the kernel to stop forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=0' )

def fixNetworkManager( root, intf ):
    """Prevent network-manager from messing with our interface,
       by specifying manual configuration in /etc/network/interfaces
       root: a node in the root namespace (for running commands)
       intf: interface name"""
    cfile = '/etc/network/interfaces'
    line = '\niface %s inet manual\n' % intf
    config = open( cfile ).read()
    if ( line ) not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    #root.cmd( 'service network-manager restart' )

def connectToInternet( net, switch='s0', rootip='10.10.10.254', subnet='10.10.10.0/24'):
    """Connect the network to the internet
       switch: switch to connect to root namespace
       rootip: address for interface in root namespace
       subnet: Mininet subnet"""
    switch = net.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]

    # Create a node in root namespace
    root = Node( 'root', inNamespace=False )

    # Prevent network-manager from interfering with our interface
    fixNetworkManager( root, 'root-eth0' )

    # Create link between root NS and switch
    link = net.addLink( root, switch )
    link.intf1.setIP( rootip, prefixLen )

    # Start network that now includes link to root namespace
    net.start()

    # Start NAT and establish forwarding
    startNAT( root )

    # Establish routes from end hosts
    for host in net.hosts:
        host.cmd( 'ip route flush root 0/0' )
        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        host.cmd( 'route add default gw', rootip )
	host.cmd( '/usr/sbin/sshd -D &' )

    return root

class TopoInternet2(Topo):
	"Single switch connected to n hosts."
	def __init__(self, **opts):
		Topo.__init__(self, **opts)
		s.append(self.addSwitch('s0',listenPort = lstPort, dpid='00:00:00:00:00:00:01:00'))
		#s.append(self.addSwitch('s1',listenPort = lstPort, dpid='00:00:00:00:00:00:01:01'))
		#s.append(self.addSwitch('s2',listenPort = lstPort, dpid='00:00:00:00:00:00:01:02'))
		#s.append(self.addSwitch('s3',listenPort = lstPort, dpid='00:00:00:00:00:00:01:03'))
		#s.append(self.addSwitch('s4',listenPort = lstPort, dpid='00:00:00:00:00:00:01:04'))
		
		#self.addLink(s[0], s[1], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		#self.addLink(s[0], s[2], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		#self.addLink(s[1], s[2], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		#self.addLink(s[1], s[3], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		#self.addLink(s[2], s[4], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		#self.addLink(s[3], s[4], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
		
		n=0
		for i in s:
			# Each host gets 50%/n of system CPU			
			h.append(self.addHost('h%s' % n, cpu=.5/len(s), ip='10.10.10.1%s'% n, mac='86:57:de:d1:06:8%s' % n))
			# 1000 Mbps, 1ms delay, 1% loss, 1000 packet queue
			self.addLink(h[n], s[n], bw=bandwidth, delay='1ms', loss=0.1, max_queue_size=1000, use_htb=True)
			print self.nodeInfo(h[n])
			n=n+1

def run():
	"Create network and run simple performance test"
	
	topo = TopoInternet2()
	net = Mininet(topo=topo, controller=lambda name: RemoteController( name,defaultIP='127.0.0.1' ,port=6633 ), host=CPULimitedHost, link=TCLink)

	topology = ET.Element('topology')
	n=0
	for i in h:
		node = ET.SubElement(topology,'node')
		node.set('id', '%s' % n) 
		node.set('name', '%s' %i )
		node.set('mac','%s' % net.get(i).MAC() )
		node.set('ip','%s' % net.get(i).IP() )
		node.set('type','%s' % 0 )
		node.set('reliability','%s' % reliability)
		n=n+1

	for i in s:
		switch = ET.SubElement(topology,'node')
		switch.set('id', '%s' % n) 
		switch.set('name', '%s' %i )
		switch.set('mac','%s' % net.get(i).MAC() )
		switch.set('ip','%s' % net.get(i).IP() )
		switch.set('listenPort','%s' % lstPort )
		switch.set('type','%s' % 1 )
		switch.set('reliability','%s' % reliability)
		for j in net.get(i).intfList():
			interface = ET.SubElement(switch,'interface')
			interface.set('name', '%s' % j )
			interface.set('mac','%s' % j.MAC() )
			interface.set('ip', '%s' % j.IP() )
			
		n=n+1
		
	for i in topo.links():
		link = ET.SubElement(topology,'link')
		link.set('from', '%s' % i[0]) 
		link.set('fromIntf', '%s' % net.get(i[0]).connectionsTo(net.get(i[1]))[0][0] ) 
		link.set('to', '%s' % i[1]) 
		link.set('toIntf', '%s' %  net.get(i[0]).connectionsTo(net.get(i[1]))[0][1] ) 
		link.set('bw', '%s' % bandwidth) 
		link.set('reliability', '%s' % reliability) 



	tree = ET.ElementTree(topology)
	tree.write('topology.xml')
	
	rootnode = connectToInternet( net )

	net.start()
	#net.pingAll()
	CLI( net )
	net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	reliability = 0.99
	bandwidth = 100
	lstPort = 7633
	s = list()
	h = list()
	run()
