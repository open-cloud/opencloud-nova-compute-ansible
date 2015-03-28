#!/usr/bin/python

from lxml import etree
import sys
import libvirt 

inst = sys.argv[1]

conn = libvirt.openReadOnly(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

try:
    dom = conn.lookupByName(inst)
except:
    print 'Failed to find domain %s' % inst
    sys.exit(1)

tree = etree.fromstring(dom.XMLDesc())

f = open("/var/lib/dnsmasq/br-nat.hosts", "r")
for line in f:
    (mac, ip) = line.strip().split(",")
    # print mac, ip
    r = tree.xpath('/domain/devices/interface/mac[@address="%s"]' % mac)
    if r:
        print ip
	exit (0)
f.close()
