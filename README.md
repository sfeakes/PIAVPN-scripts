# PIAVPN-scripts

Helper scripts for PIA VPN port forwarding. This is for PIA VPN's Nextgen servers only.

The outline for portforwarding of these scripts were taken from the below repo, so credit to them :-
https://github.com/pia-foss/manual-connections

Problem with the above is it's designed to start your vpn connection and also do portforward. The scripts in the above repo simply won't work when something else starts the vpn connection. There are also some other issues with the above, that make them not really optimal for the way I (and many others) like to use a VPN.  
The scripts in this repo are designed for the system (i.e any of the Linux service managers) to start and manage the vpn connection and for the script to use that connection to make the portforward call.

#
## piavpn-portforward.sh
This is designed to request a portforward from pia over any already established connection. PIA VPN now needs a heartbeat for port forwarding, so you will need to run every 15mins or so from a chron job (or equiv).
Simply edit the config variables in the script and away you go.

Main variables to edit are the below.
```
VPN_INTERFACE="tun0"
CREDENTIALS="/etc/openvpn/user.txt"
-- OR --
PIA_USER=piauserxx
PIA_PASS=piapassxx
```

It depends on the following system utilities, most are already installed, if not `sudo apt-get install xxxx` will do it for most linux systems. `curl, ip, ifconfig, traceroute, jq, dig`

Firt think to check is you have all the dependancy installed, Run with the below to check.  
`./piavpn-portforward.sh check_install`

All script options are below, hopefully the names are self explanatory.
  * get_public_ip_address
  * get_vpn_ip_address
  * get_public_port
  * bind_public_port
  * get_status (optional parameter `extended`)
  * check_install



To get port.  PIA can change this port on you, so the application that needs the port forward information should call this at a regular interval.  
`./piavpn-portforward.sh get_public_port`

Heartbeat, should be run on ~15min schedule. PIA will drop your portforward if you don't keep a heartbeat to them. If your application is calling `get_public_port` at an 15min interval or less, you do not need to make the below call.  
`./piavpn-portforward.sh bind_public_port`
 
#
  
  
## rtorrent-functions.sh
No documentation yet.  this will configure rTorrent to pia vpn and also keep everything up to date as ports / ip's / connections change.

This script has all functionality of `piavpn-portforward.sh`, so there is no need to install both.

The basic idea of this script is it keeps rtorrent insync with pia vpn & port forwarding, making sure not to loose your anonymity. It get's called from 3 parts of your system:-
* Called from `rtorrent` to get all public network information (bind ip, public ip, public port forwatd), if PIA portworwarding is not active on any of these calls, the script will activate it.
* Called from vpn connecting or closing. `openvpn` or `WireGuard`
* Called from `cron` as a health check, it will stop / start / restart vpn & rtorrent depending on status of connections.