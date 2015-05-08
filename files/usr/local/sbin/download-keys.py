#!/usr/bin/python

import os
import pwd, grp
import urllib2
import socket
import json

xosapi = "http://10.254.1.22:8000"

hostname = socket.gethostname()

# Call XOS REST API
urlCmd = xosapi + "/xoslib/sshkeys/?node_name=%s" % hostname
req = urllib2.urlopen(urlCmd)
response = req.read()

# Parse json
keyinfo = json.loads(response)

for instance in keyinfo:
    try: instance['id']
    except:
        print "Unexpected data from XOS: %s" % instance
        continue

    try:
        keydir= "/home/%s/.ssh/" % instance['id']
        if not os.path.isdir(keydir):
            print "%s: %s doesn't exist, skipping" % (instance['id'], keydir)
            continue
    
        keyfile = keydir + "authorized_keys"
        f = open(keyfile, 'w')
        for key in instance['public_keys']:
            f.write(key + '\n')
        f.close()
        
        os.chmod(keyfile, 0600)
        uid = pwd.getpwnam(instance['id']).pw_uid
        gid = grp.getgrnam('slices').gr_gid
        os.chown(keyfile, uid, gid)

        print "%s: Installing SSH keys\t[OK]" % instance['id']
    except:
        print "%s: Installing SSH keys\t[FAILED]" % instance['id']
        pass
