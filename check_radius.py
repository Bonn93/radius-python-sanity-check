#!/usr/bin/python
'''
@ Original Author - Lee Webb
@note: Conducts an Authentication test against a nominated Radius server.
    Currently only supports MSCHAP2 based authentication as per RFC 2759.
    Primarily to be used by a monitoring system to ensure that a Radius
    server is available & processing Auth requests properly
@return: OK with a return code of 0 if Auth passes;
    or CRITICAL with a return code 2 if Auth fails or there was a timeout. 
'''
import sys
sys.path.append(sys.path[0] + "/lib/") # to be fixed with updated folder structure
import packet
from client import Client
from dictionary import Dictionary 
import mschap2
from socket import gethostname, gethostbyname
from time import time
import getopt

def main():
    opts = {}
    opts = getopts()
    send(opts)
    
def getopts():
    types = { "mschap2":1, "mschap":1, "chap":1, "pap":1 }
    required = [ "port", "dict", "host", "user", "pass", "type", "secret"]
    options = {}
    options["port"] = 1812
    options["dict"] = sys.path[0] + "/dicts/dictionary"
    options["type"] = "mschap2"
    options["verbose"] = False
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hu:p:h:s:d:t:p:v",
            ["help", "username=", "password=", "host=", "secret=", "type=", "port=", "dictionary=", "verbose"])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)    
    for o, a in opts:
        if o in ("-u", "--username"):
            options["user"] = a
        elif o in ("-p", "--password"):
            options["pass"] = a
        elif o in ("-h", "--host"):
            options["host"] = a
        elif o in ("-s", "--secret"):
            options["secret"] = a
        elif o in ("-p", "--port"):
            options["port"] = int(a)
        elif o in ("-t", "--type"):
            if not types.has_key(a):
                print "Unsupported auth type: %s" % a
                sys.exit(1)
            options["type"] = a
        elif o in ("-d", "--dictionary"):
            if not os.path.isfile(a):
                print "Unable to read dictionary: %s" % a
            options["dict"] = a
        elif o in ("-v", "--verbose"):
            options["verbose"] = True
        else:
            assert False, "Unhandled option"
    for key in range(0,len(required)):
        if not options.has_key(required[key]):
            print "required argument missing: %s" % required[key]
            usage()
            sys.exit(1)
    return options


def send(opts):
    hostname = gethostname()
    address = gethostbyname(hostname)
    radius = Client(server = opts["host"], secret = opts["secret"], authport = opts["port"], dict = Dictionary(opts["dict"]))
    request = radius.CreateAuthPacket(code = packet.AccessRequest)
    if opts["verbose"]:
        print "[DEBUG] assembling packet attributes"
    attrs = { "User-Name":opts["user"], "NAS-Identifier":hostname, "NAS-IP-Address":address }
    for key in attrs.keys():
        request[key] = attrs[key]
    del attrs
    if opts["verbose"]:
        print "[DEBUG] auth method: %s" % opts["type"] 
    if opts["type"] == "mschap2":
        auth = mschap2.MSCHAP2()
    elif opts["type"] in ("mschap", "chap", "pap"):
        print "Unsupported authentication type: %s" % opts["type"]
    authAttrs = {}
    authAttrs = auth.getAuthAttrs(opts["user"], opts["pass"])
    for key in authAttrs.keys():
        request[key] = authAttrs[key]
    del authAttrs
    if opts["verbose"]:
        print "[DEBUG] dumping request attributes..."
        for key in request.keys():
            print "[DEBUG]\t\t %s : %s" % (key,request[key])
    tsStart = time()
    try:
    	reply = radius.SendPacket(request)
    except:
        print "CRITICAL: Timeout sending Access-Request"
        sys.exit(2)
    tsStop = time()
    if opts["verbose"]:
        print "[DEBUG] dumping reply attributes..."
        for key in reply.keys():
            print "[DEBUG]\t\t %s : %s" % (key,reply[key])
    if reply.code == packet.AccessAccept:
        print "OK: Access-Accept in: %0.2f seconds" % (tsStop - tsStart)
        sys.exit(0)
    else:
        print "CRITICAL: Access-Reject in: %0.2f seconds" % (tsStop - tsStart)
        sys.exit(2)


def usage():
    print "check_radius.py --username string --password string --host string --secret string <--dict file> <--port int>"
    print "where:"
    print "\tusername : username to send in User-Name attribute"
    print "\tpassword : password to send for auth against username"
    print "\thost     : radius server to send auth request to"
    print "\tsecret   : shared secret with the radius server"
    print "\tdict     : dictionary file for radius attributes defaults to: dicts/dictionary"
    print "\tport     : radius port: defaults to 1812"
    sys.exit(1)


if __name__ == "__main__":
    main()
