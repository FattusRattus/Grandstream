# GXV3240 Exploits
Various exploit scripts for Grandstream GXV3240 Phones

Description
----
Inspired by first seeing a video on Youtube: https://www.youtube.com/watch?v=WYkp6KivZUo

I was interested to working on scripts for some of the Grandstream phones I have to deal with. 

After more research and further inspired by:

http://davidjorm.blogspot.com/

https://github.com/scarvell/grandstream_exploits

Later after working on the scripts, I also found:
https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=23920


The Scripts
----

Currently, there are just two scripts:

gxv3240-cam.py - This will scan a subnet for GXV3240 handsets, attempt to exploit them and exfiltrate images taken with the phone's onboard camera, having the option to also take pictures with the onboard camera. It does this via a built in TFTP server, which will create the folder tftp-cam.

gxv3240-getpass.py - This is a password recovery script.


Requirements
----
The only out of the ordinary requirement is tftpy module (pip installl tftpy). It runs best from Kali, on a Raspberry Pi 3/4 and Windows. Ihave tried to make it platform friendly and pyinstaller friendly.

