# PIAVPN-scripts

Helper scripts for PIA VPN port forwarding. This is for PIA VPN's Nextgen servers only.

The outline the portforwarding of these scripts was taken from the below repo, so credit to them :-
https://github.com/pia-foss/manual-connections

Problem is the above is it's designed to start your vpn connection and also do portforward. The scripts simply won't work when something else starts the vpn connection.
The scripts in this repo are designed for the system (i.e any of the Linux service managers) to start and manage the vpn connection and for the script to use that connection to make the portforward call.


## piavpn-portforward.sh
This is designed to request a portforward from pia over any already established connection. PIA VPN now needs a heartbeat for port forwarding, so you will need to run every 15mins or so from a chron job (or equiv).
Simply edit the config variables in the script and away you go.

Main variables to edit are the below.
```
VPN_INTERFACE="tun0"
CREDENTIALS='/etc/openvpn/user.txt'
-- OR --
PIA_USER=piauserxxxxxxx
PIA_PASS=pispassxxxxxx
```

Run this first to make sure everything is set.  
`./piavpn-portforward.sh check_install`

To get port.  PIA can change this port on you, so the application that needs the port forward information should call this at a regular interval.  
`./piavpn-portforward.sh get_public_port`

Heartbeat, should be run on ~15min schedule. PIA will drop your portforward if you don't keep a heartbeat to them. If your application is calling `get_public_port` at an 15min interval or less, you do not need to make the below call.  
`./piavpn-portforward.sh bind_public_port`

Other options that can be useful.    
`./piavpn-portforward.sh get_status`  
`./piavpn-portforward.sh get_vpn_ip_address`  
`./piavpn-portforward.sh get_public_ip_address`  




## rtorrent-functions.sh
No documentation yet.  this will configure rTorrent to pia vpn and also keep everything up to date as ports / ip's / connections change.