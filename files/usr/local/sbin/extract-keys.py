#!/usr/bin/python

import libvirt
import os
import subprocess
import pwd, grp
import traceback

conn = libvirt.openReadOnly(None)

for dom in conn.listAllDomains():
        sshdir = "/home/%s/.ssh/" % dom.name()
        if dom.isActive() and os.path.isdir(sshdir):
                keyfile = sshdir + 'authorized_keys'
                cmd = "guestfish --ro -d %s -i cat /home/ubuntu/.ssh/authorized_keys" % dom.name()
                try:
                    keys = subprocess.check_output(cmd, shell=True)
                except:
                    print "exception which running guestfish"
                    traceback.print_exc()
                    continue

                f = open(keyfile, 'w')
                f.write(keys)
                f.close()

                os.chmod(keyfile, 0600)
                uid = pwd.getpwnam(dom.name()).pw_uid
                gid = grp.getgrnam('slices').gr_gid
                os.chown(keyfile, uid, gid)

