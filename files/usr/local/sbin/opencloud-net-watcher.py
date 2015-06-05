#!/usr/bin/python

"""
    Poll neutron for changes in ports. Run opencloud-net if a change is
    detected.
"""

import json
import logging
import optparse
import os
import re
import sys
import subprocess
import time
import traceback
from ConfigParser import ConfigParser
from neutronclient.v2_0 import client

class OpenCloudNetWatcher:
    def __init__(self, daemonize):
        self.ports = {}
        parser = ConfigParser()
        parser.read("/etc/nova/nova.conf")
        self.neutron_username = parser.get("DEFAULT", "neutron_admin_username")
        self.neutron_password = parser.get("DEFAULT", "neutron_admin_password")
        self.neutron_tenant_name = parser.get("DEFAULT", "neutron_admin_tenant_name")
        self.neutron_auth_url = parser.get("DEFAULT", "neutron_admin_auth_url")

        if daemonize:
            self.daemon()

    # from opencloud-net.py
    def convert_ovs_output_to_dict(self, out):
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

    # from opencloud-net.py
    def get_local_neutron_ports(self):
        ports = []

        # Get local information for VM interfaces from OvS
        ovs_out = subprocess.check_output(['/usr/bin/ovs-vsctl', '-f', 'json', 'find',
                                           'Interface', 'external_ids:iface-id!="absent"'])
        records = self.convert_ovs_output_to_dict(ovs_out)

        if records:
            # Extract Neutron Port IDs from OvS records
            port_ids = []
            for rec in records:
                port_ids.append(rec['external_ids']['iface-id'])

            # Get the full info on these ports from Neutron
            neutron = client.Client(username=self.neutron_username,
                                    password=self.neutron_password,
                                    tenant_name=self.neutron_tenant_name,
                                    auth_url=self.neutron_auth_url)
            ports = neutron.list_ports(id=port_ids)['ports']

        return ports

    def did_something_change(self):
        ports = self.get_local_neutron_ports()
        ids = [port["id"] for port in ports]

        something_changed = False

        for port in ports:
            port_id = port["id"]
            if not port_id in self.ports:
                logging.info("new port %s" % port_id)
                something_changed = True
            else:
                existing_port = self.ports[port_id]
                if port.get("nat:forward_ports",None) != existing_port.get("nat:forward_ports", None):
                    logging.info("forwarding on port %s changed" % port_id)
                    something_changed = True

            self.ports[port_id] = port

        for port_id in self.ports.keys():
            if not port_id in ids:
                logging.info("deleted port %s" % port_id)
                del self.ports[port_id]
                something_changed = True

        return something_changed

    def get_lan_tag(self):
        tag = None
        cmd = ['/usr/bin/ovs-ofctl', 'dump-flows', 'br-lan']
        out = subprocess.check_output(cmd)
        match = re.search("dl_vlan=([0-9]+) ", out)
        if match:
            tag = match.groups()[0]
        return tag

    # Handle the case where Neutron has made a change that we need to undo
    # In particular, look for interfaces with the "LAN network" tag
    # If any are found, we will run opencloud-net.py to remove them
    def action_needed(self):
        action_needed = False

        cmd = ['/usr/bin/ovs-vsctl', 'list-ports', 'br-int']
        ifaces = subprocess.check_output(cmd).rstrip().split('\n')
        # print ifaces

        lan_tag = self.get_lan_tag()
        # print lan_tag

        for iface in ifaces:
            cmd = ['/usr/bin/ovs-vsctl', 'get', 'Port', iface, 'tag']
            tag = subprocess.check_output(cmd).rstrip()
            if tag == lan_tag:
                action_needed = True

        return action_needed

    def run_once(self):
        try:
            if self.did_something_change() or self.action_needed():
                logging.info("something changed - running opencloud-net.py")
                os.system("/usr/local/sbin/opencloud-net.py")
            else:
                pass
        except:
            logging.error("Error in run_once: BEG TRACEBACK"+"\n"+traceback.format_exc().strip("\n"))
            logging.error("Error in run_once: END TRACEBACK")


    def run_loop(self):
        while True:
            self.run_once()
            time.sleep(30)

    # after http://www.erlenstar.demon.co.uk/unix/faq_2.html
    def daemon(self):
        """Daemonize the current process."""
        if os.fork() != 0: os._exit(0)
        os.setsid()
        if os.fork() != 0: os._exit(0)
        os.chdir('/')
        os.umask(0022)
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        # xxx fixme - this is just to make sure that nothing gets stupidly lost - should use devnull
        crashlog = os.open('/var/log/opencloud-net-watcher.daemon', os.O_RDWR | os.O_APPEND | os.O_CREAT, 0644)
        os.dup2(crashlog, 1)
        os.dup2(crashlog, 2)

def main():
    parser = optparse.OptionParser()
    parser.add_option('-d', '--daemon', action='store_true', dest='daemon', default=False,
                      help='run daemonized')
    parser.add_option('-l', '--logfile', action='store', dest='logfile', default="/var/log/opencloud-net-watcher",
                  help='log file name')

    (options, args) = parser.parse_args()

    logging.basicConfig(filename=options.logfile,level=logging.INFO)

    watcher = OpenCloudNetWatcher(daemonize = options.daemon)
    watcher.run_loop()

if __name__ == "__main__":
   main()

