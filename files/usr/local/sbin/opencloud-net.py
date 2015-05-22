#!/usr/bin/python

"""
This program sets up dnsmasq and iptables to support the "Private-Nat"
and "Public" network models for OpenCloud.  It communicates with OvS
on the local node and Neutron to gather information about the virtual
interfaces instantiated by Neutron.  It uses this information to:

* add the Neutron-assigned IP address to the vif via dnsmasq
* set up port forwarding rules through the NAT using iptables

The iptables configuration uses a chain called 'opencloud-net' to
hold the port forwarding rules.  This is called from the PREROUTING
chain of the nat table. The chain is flushed and rebuilt every time
the plugin runs to avoid stale rules.  This plugin also sets up the
MASQ rule in the POSTROUTING chain.

NOTES: 
* Currently the port forwarding rules are driven from a per-node config
  file, not from state in Neutron
"""

# system provided modules
import fcntl
import os, string, time, socket, sys
from socket import inet_aton
import subprocess, signal
import json
from ConfigParser import ConfigParser
import socket, netifaces, netaddr
import re

# Neutron modules
from neutronclient.v2_0 import client

plugin = "opencloud-net"

nat_net_name = "nat-net"
nat_net_dev = "br-nat"
nat_net_id = None

site_net_name = "ext-net"
site_net_dev = None
site_net_id = None

lan_net_name = "lan-net"
lan_net_dev = "br-lan"
lan_net_id = None

# Handle differences between Ubuntu 14.04, 12.04, MAAS, etc.
# THis works but it's pretty sloppy
interfaces = netifaces.interfaces()
for dev in ['br-ex', 'em1', 'br0', 'eth0', 'eth2']:
    if dev in interfaces and 2 in netifaces.ifaddresses(dev):
        site_net_dev = dev
        break

neutron_auth_url = None
neutron_username = None
neutron_password = None
neutron_tenant_name = None

# Pretty stupid right now, but should get the job done
def set_ip_address(dev, addr, cidr):
    (net, bits) = cidr.split('/')
    addrwithcidr = addr + '/' + bits
    cmd = ["/sbin/ip", "addr", "change", addrwithcidr, "dev", dev]
    try:
        subprocess.call(cmd)
    except:
        pass
        
def get_addrinfo(ifname):
    addrs = netifaces.ifaddresses(ifname)
    ipinfo = addrs[socket.AF_INET][0]
    address = ipinfo['addr']
    netmask = ipinfo['netmask']
    cidr = netaddr.IPNetwork('%s/%s' % (address, netmask))
    return (address, str(cidr.cidr))

def get_iface_by_mac(mac):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        iface_mac = addrs[netifaces.AF_LINK][0]["addr"]
        if iface_mac == mac:
            return iface
    return None

def move_port(tap_iface, frombridge, tobridge):
    print "%s: Move %s from %s to %s" % (plugin, tap_iface, frombridge, tobridge)

    # Save external_ids. They get erased in the move.
    cmd = ['/usr/bin/ovs-vsctl', 'get', 'Interface', tap_iface, 'external_ids']
    external_ids = subprocess.check_output(cmd).rstrip()
    # print external_ids

    cmd = ['/usr/bin/ovs-vsctl', 'del-port', tap_iface]
    subprocess.check_call(cmd)

    cmd = ['/usr/bin/ovs-vsctl', 'add-port', tobridge, tap_iface]
    subprocess.check_call(cmd)

    # Restore external ids.
    cmd = ['/usr/bin/ovs-vsctl', 'set', 'Interface', tap_iface,
           "external_ids=%s" % external_ids]
    subprocess.check_call(cmd)

# Should possibly be using python-iptables for this stuff
def run_iptables_cmd(args):
    cmd = ['/sbin/iptables'] + args
    print('%s: %s' % (plugin, ' '.join(cmd)))
    subprocess.check_call(cmd)

def del_iptables_rule(table, chain, args):
    iptargs = ['-t', table, '-C',  chain] + args
    try:
        run_iptables_cmd(iptargs)
    except:
        #print "rule does not exist", iptargs
        return

    iptargs[2] = '-D'
    try:
        run_iptables_cmd(iptargs)
    except:
        print('%s: FAILED to delete iptables rule' % plugin, iptargs)

def add_iptables_rule(table, chain, args, pos = None):
    iptargs = ['-t', table, '-C',  chain] + args
    try:
        run_iptables_cmd(iptargs)
        #print "rule already exists", iptargs
    except:
        if pos:
            iptargs = ['-t', table, '-I', chain, str(pos)] + args
        else:
            iptargs[2] = '-A'
        try:
            run_iptables_cmd(iptargs)
        except:
            print('%s: FAILED to add iptables rule' % plugin)

def reset_iptables_chain():
    try:
        # Flush the opencloud-nat chain
        run_iptables_cmd(['-t', 'nat', '-F', plugin])
    except:
        # Probably the chain doesn't exist, try creating it
        run_iptables_cmd(['-t', 'nat', '-N', plugin])

    add_iptables_rule('nat', 'PREROUTING', ['-j', plugin])

def fix_udp_mangle():
    # get rid of the existing UDP mangle rule that is attached to virbr0
    del_iptables_rule('mangle', 'POSTROUTING', ['-p', 'udp', '--dport', 'bootpc', '-o', 'virbr0', '-j', 'CHECKSUM', '--checksum-fill'])

    # add the new rule that is attached to all devices
    add_iptables_rule('mangle', 'POSTROUTING', ['-p', 'udp', '--dport', 'bootpc', '-j', 'CHECKSUM', '--checksum-fill'])

# Nova blocks packets from external addresses by default.
# This is hacky but it gets around the issue.
def unfilter_ipaddr(dev, ipaddr):
    add_iptables_rule(table = 'filter',
                      chain = 'nova-compute-sg-fallback',
                      args = ['-d', ipaddr, '-j', 'ACCEPT'],
                      pos = 1)

# Enable iptables MASQ for a device
def add_iptables_masq(dev, cidr):
    args = ['-s',  cidr, '!',  '-d',  cidr, '-j', 'MASQUERADE']
    add_iptables_rule('nat', 'POSTROUTING', args)

def get_pidfile(dev):
    return '/var/run/dnsmasq-%s.pid' % dev

def get_leasefile(dev):
    return '/var/lib/dnsmasq/%s.leases' % dev

def get_hostsfile(dev):
    return '/var/lib/dnsmasq/%s.hosts' % dev

# Check if dnsmasq already running
def dnsmasq_running(dev):
    pidfile = get_pidfile(dev)
    try:
        pid = open(pidfile, 'r').read().strip()
        if os.path.exists('/proc/%s' % pid):
            return True
    except:
        pass
    return False
    
def dnsmasq_remove_lease(dev, ip, mac):
    cmd = ['/usr/bin/dhcp_release', dev, ip, mac]
    try:
        subprocess.check_call(cmd)
    except:
        print('%s: dhcp_release failed' % (plugin))

def dnsmasq_sighup(dev):
    pidfile = get_pidfile(dev)
    try:
        pid = open(pidfile, 'r').read().strip()
        if os.path.exists('/proc/%s' % pid):
            os.kill(int(pid), signal.SIGHUP)
            print("%s: Sent SIGHUP to dnsmasq on dev %s" % (plugin, dev))
    except:
        print("%s: Sending SIGHUP to dnsmasq FAILED on dev %s" % (plugin, dev))

# Enable dnsmasq for this interface.
# It's possible that we could get by with a single instance of dnsmasq running on
# all devices but I haven't tried it.
def start_dnsmasq(dev, ipaddr, forward_dns=True, authoritative=False, dns_addr=None):
    if not dnsmasq_running(dev):
        # The '--dhcp-range=<IP addr>,static' argument to dnsmasq ensures that it only
        # hands out IP addresses to clients listed in the hostsfile
        cmd = ['/usr/sbin/dnsmasq',
               '--strict-order',
               '--bind-interfaces',
               '--local=//',
               '--domain-needed',
               '--pid-file=%s' % get_pidfile(dev),
               '--conf-file=',
               '--interface=%s' % dev,
               '--except-interface=lo',
               '--dhcp-leasefile=%s' % get_leasefile(dev),
               '--dhcp-hostsfile=%s' % get_hostsfile(dev),
               '--dhcp-no-override',
               '--dhcp-range=%s,static' % ipaddr]

        if authoritative:
            cmd.append('--dhcp-authoritative')

        # Turn off forwarding DNS queries, only do DHCP
        if forward_dns == False:
            cmd.append('--port=0')

        # Tell the guest's resolver to use a particular DNS server
        if dns_addr:
            cmd.append("--dhcp-option=6,%s" % dns_addr)

        try:
            print('%s: starting dnsmasq on device %s' % (plugin, dev))
            subprocess.check_call(cmd)
        except:
            print('%s: FAILED to start dnsmasq for device %s' % (plugin, dev))
            print(' '.join(cmd))

def convert_ovs_output_to_dict(out):
    decoded = json.loads(out.strip())
    headings = decoded['headings']
    data = decoded['data']

    records = []
    for rec in data:
        mydict = {}
        for i in range(0, len(headings) - 1):
            if not isinstance(rec[i], list):
                mydict[headings[i]] = rec[i]
            else:
                if rec[i][0] == 'set':
                    mydict[headings[i]] = rec[i][1]
                elif rec[i][0] == 'map':
                    newdict = {}
                    for (key, value) in rec[i][1]:
                        newdict[key] = value
                    mydict[headings[i]] = newdict
                elif rec[i][0] == 'uuid':
                    mydict['uuid'] = rec[i][1]
        records.append(mydict)

    return records


# Get a list of local VM interfaces and then query Neutron to get
# Port records for these interfaces.
def get_local_neutron_ports():
    ports = []

    # Get local information for VM interfaces from OvS
    ovs_out = subprocess.check_output(['/usr/bin/ovs-vsctl', '-f', 'json', 'find', 
                                       'Interface', 'external_ids:iface-id!="absent"'])
    records = convert_ovs_output_to_dict(ovs_out)

    if records:
        # Extract Neutron Port IDs from OvS records
        port_ids = []
        for rec in records:
            port_ids.append(rec['external_ids']['iface-id'])

        # Get the full info on these ports from Neutron
        neutron = client.Client(username=neutron_username,
                                password=neutron_password,
                                tenant_name=neutron_tenant_name,
                                auth_url=neutron_auth_url)
        ports = neutron.list_ports(id=port_ids)['ports']

    return ports


# Generate a dhcp-hostsfile for dnsmasq.  The purpose is to make sure
# that the IP address assigned by Neutron appears on NAT interface.
def write_dnsmasq_hostsfile(dev, ports, net_id):
    print("%s: Writing hostsfile for %s" % (plugin, dev))
    
    masqfile = get_hostsfile(dev)
    masqdir = os.path.dirname(masqfile)
    if not os.path.exists(masqdir):
        os.makedirs(masqdir)
       
    # Clean up old leases in the process
    leases = {} 
    leasefile = get_leasefile(dev)
    try:
        f = open(leasefile, 'r')
        for line in f:
            fields = line.split()
            try:
                leases[fields[2]] = fields[1]
            except:
                pass
        f.close()
    except:
        pass
        
    f = open(masqfile, 'w')
    for port in ports:
        if port['network_id'] == net_id:
            mac_addr = port['mac_address']
            ip_addr = port['fixed_ips'][0]['ip_address']
            entry = "%s,%s\n" % (mac_addr, ip_addr)
            f.write(entry)
            print("%s:   %s" % (plugin, entry.rstrip()))

            if ip_addr in leases and leases[ip_addr] != mac_addr:
                dnsmasq_remove_lease(dev, ip_addr, leases[ip_addr])
                print("%s: removed old lease for %s" % (plugin, ip_addr))
    f.close()

    # Send SIGHUP to dnsmasq to make it re-read hostsfile
    dnsmasq_sighup(dev)

def add_fw_rule(protocol, fwport, ipaddr):
    print "%s: fwd port %s/%s to %s" % (plugin, protocol, fwport, ipaddr)
    add_iptables_rule('nat', plugin, ['-i', site_net_dev,
                                      '-p', protocol, '--dport', str(fwport),
                                      '-j', 'DNAT', '--to-destination', ipaddr])

# Set up iptables rules in the 'opencloud-net' chain based on
# the nat:forward_ports field in the Port record.
def set_up_port_forwarding(dev, ports):
    if os.path.exists('/usr/local/etc/portfwd.cfg'):
        try:
            with open('/usr/local/etc/portfwd.cfg', 'r') as fp:
                for line in fp:
                    try:
                        (protocol, port, ipaddr) = line.strip().split()
                        if protocol in ['tcp', 'udp']:
                            add_fw_rule(protocol, port, ipaddr)
                    except:
                        pass
        except:
            print("%s: Could not read port forward file" % plugin)
            pass

    for port in ports:
        if (port['network_id'] == nat_net_id) and port.get('nat:forward_ports',None):
            for fw in port['nat:forward_ports']:
                ipaddr = port['fixed_ips'][0]['ip_address']
                protocol = fw['l4_protocol']
                fwport = fw['l4_port']

                #unfilter_ipaddr(dev, ipaddr)
                add_fw_rule(protocol, fwport, ipaddr)

def get_net_id_by_name(name):
    neutron = client.Client(username=neutron_username,
                            password=neutron_password,
                            tenant_name=neutron_tenant_name,
                            auth_url=neutron_auth_url)

    net = neutron.list_networks(name=name)
    net_id = net['networks'][0]['id']

    return net_id

def get_subnet_network(net_id):
    neutron = client.Client(username=neutron_username,
                            password=neutron_password,
                            tenant_name=neutron_tenant_name,
                            auth_url=neutron_auth_url)

    subnets = neutron.list_subnets(network_id=net_id)
    
    ipaddr = subnets['subnets'][0]['gateway_ip']
    cidr = subnets['subnets'][0]['cidr']

    return (ipaddr,cidr)
    
def block_remote_dns_queries(ipaddr, cidr):
    for proto in ['tcp', 'udp']:
        add_iptables_rule('filter', 'INPUT',
                            ['!', '-s', cidr, '-d', ipaddr, '-p', proto,
                            '--dport', '53', '-j', 'DROP'])

def allow_remote_dns_queries(ipaddr, cidr):
    for proto in ['tcp', 'udp']:
        del_iptables_rule('filter', 'INPUT',
                            ['!', '-s', cidr, '-d', ipaddr, '-p', proto,
                            '--dport', '53', '-j', 'DROP'])

def move_lan_ports(dev, ports, net_id):
    print("%s: Moving LAN ports to %s" % (plugin, dev))

    for port in ports:
        if port['network_id'] == net_id:
            tap_mac = re.sub("^fa:","fe:", port['mac_address'])
            tap_iface = get_iface_by_mac(tap_mac)
            if tap_iface:
                cmd = ['/usr/bin/ovs-vsctl', 'port-to-br', tap_iface]
                bridge = subprocess.check_output(cmd).rstrip()
                if bridge != dev:
                    move_port(tap_iface, bridge, dev)
                else:
                    print("%s: %s already on %s" % (plugin, tap_iface, dev))
            else:
                print("%s: No iface found matching %s" % (plugin, tap_mac))


def start():
    global neutron_username
    global neutron_password
    global neutron_tenant_name
    global neutron_auth_url

    print("%s: plugin starting up..." % plugin)

    parser = ConfigParser()
    parser.read("/etc/nova/nova.conf")
    neutron_username = parser.get("DEFAULT", "neutron_admin_username")
    neutron_password = parser.get("DEFAULT", "neutron_admin_password")
    neutron_tenant_name = parser.get("DEFAULT", "neutron_admin_tenant_name")
    neutron_auth_url = parser.get("DEFAULT", "neutron_admin_auth_url")

def main(argv):
    global nat_net_id
    global site_net_id
    global lan_net_id

    lock_file = open("/var/lock/opencloud-net", "w")
    try:
        fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        if e.errno == errno.EAGAIN:
            print >> sys.stderr, "Script is already running."
            sys.exit(-1)

    start()

    if not nat_net_id:
        try:
            nat_net_id = get_net_id_by_name(nat_net_name)
        except:
            print("%s: no network called %s..." % (plugin, nat_net_name))
            sys.exit(1)

    print("%s: %s id is %s..." % (plugin, nat_net_name, nat_net_id))

    if not site_net_id:
        try:
            site_net_id = get_net_id_by_name(site_net_name)
            print("%s: %s id is %s..." % (plugin, site_net_name, site_net_id))
        except:
            print("%s: no network called %s..." % (plugin, site_net_name))

    if not lan_net_id:
        try:
            lan_net_id = get_net_id_by_name(lan_net_name)
            print("%s: %s id is %s..." % (plugin, lan_net_name, lan_net_id))
        except:
            print("%s: no network called %s..." % (plugin, lan_net_name))

    reset_iptables_chain()
    ports = get_local_neutron_ports()
    # print ports

    # Set IP address on br-nat if necessary
    (nat_ip_addr, nat_cidr) = get_subnet_network(nat_net_id)
    set_ip_address(nat_net_dev, nat_ip_addr, nat_cidr)

    # Process Private-Nat networks
    add_iptables_masq(nat_net_dev, nat_cidr)
    write_dnsmasq_hostsfile(nat_net_dev, ports, nat_net_id)
    set_up_port_forwarding(nat_net_dev, ports)
    start_dnsmasq(nat_net_dev, nat_ip_addr, authoritative=True)

    # Process Public networks
    # Need iptables rule to block requests from outside...
    if site_net_id:
        write_dnsmasq_hostsfile(site_net_dev, ports, site_net_id)
        (ipaddr, cidr) = get_addrinfo(site_net_dev)

        # blocking remote queries isn't needed now that DNS is not listening on
        # the host's IP
        #block_remote_dns_queries(ipaddr, cidr)
        allow_remote_dns_queries(ipaddr, cidr)

        start_dnsmasq(site_net_dev, ipaddr, authoritative=True, forward_dns=False, dns_addr="8.8.8.8")

    # Process LAN network
    """
    if lan_net_id:
        move_lan_ports(lan_net_dev, ports, lan_net_id)
    """

    fix_udp_mangle()

if __name__ == "__main__":
   main(sys.argv[1:])
