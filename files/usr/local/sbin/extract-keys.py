#!/usr/bin/python

import libvirt
import os
import subprocess
import pwd, grp
import traceback
import xml.etree.ElementTree as ET
import time

def extract_ubuntu_keys(domain):
    destdir = "/home/%s/.ssh" % domain
    if not os.path.isdir(destdir):
        print "%s doesn't exist, aborting" % destdir
        return False

    src = '/home/ubuntu/.ssh/authorized_keys'
    dest = destdir + '/authorized_keys'
    cmd = "guestfish --ro -d %s -i copy-out %s %s " % (domain, src, destdir)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    except:
        # print "exception which running guestfish"
        # traceback.print_exc()
        return False

    os.chmod(dest, 0600)
    uid = pwd.getpwnam(domain).pw_uid
    gid = grp.getgrnam('slices').gr_gid
    os.chown(dest, uid, gid)

    return True

def extract_openwrt_keys(domain):
    destdir = "/home/%s/.ssh" % domain
    if not os.path.isdir(destdir):
        print "%s doesn't exist, aborting" % destdir
        return False

    src = '/etc/dropbear/authorized_keys'
    dest = destdir + '/authorized_keys'
    cmd = "guestfish --ro -d %s -m /dev/sda2:/ copy-out %s %s " % (domain, src, destdir)
    try:
        out = subprocess.check_call(cmd, stderr=subprocess.STDOUT, shell=True)
    except:
        # print "exception which running guestfish"
        # traceback.print_exc()
        return False

    os.chmod(dest, 0600)
    uid = pwd.getpwnam(domain).pw_uid
    gid = grp.getgrnam('slices').gr_gid
    os.chown(dest, uid, gid)

    return True

# The problem is that the authorized_keys file written inside the slice
# is not always visible to guestfish.  Probably KVM has not written back
# then changes to the backing store.
#
# Not sure what this does exactly, but often it solves the problem.
# Also not sure if it has unintended side-effects.
def sync_storage(dom):
    root = ET.fromstring(dom.XMLDesc())
    for disk in root.findall("devices/disk/target"):
        try:
            dev = disk.get("dev")
            print "%s: Performing block commit on %s" % (dom.name(), dev)
            #dom.blockCommit(dev, None, None)
            cmd = "virsh blockcommit %s %s" % (dom.name(), dev)
            out = subprocess.check_call(cmd, stderr=subprocess.STDOUT, shell=True)
        except:
            # Looks like this always fails but it seems to do the trick
            pass


conn = libvirt.openReadOnly(None)

for dom in conn.listAllDomains():
    if dom.isActive():
        sync_storage(dom)
        success = extract_ubuntu_keys(dom.name())
        if success:
            print "%s: Extracting Ubuntu keys\t[OK]" % dom.name()
        else:
            success = extract_openwrt_keys(dom.name())
            if success:
                print "%s: Extracting OpenWRT keys\t[OK]" % dom.name()
            else:
                print "%s: Extracting SSH keys\t[FAILED]" % dom.name()
