# PIAVPN-scripts

Helper scripts for PIA VPN port forwarding.

The outline the portforwarding of these scripts was taken fromthe below repo, so credit to them :-
https://github.com/pia-foss/manual-connections

Problem is the above is it's designed to start your vpn connection and also do portforward, they simply won't work when something else starts the vpn connection.
The scripts in this repo are designed for the system to start the vpn connection and for the script to use that connection.


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

Run this first to make sure everything is set  
`piavpn-portforward.sh check_install`

To get port  
`piavpn-portforward.sh get_public_port`

Heartbeat, should be run on ~15min schedule  
`piavpn-portforward.sh bind_public_port`

Other options that can be useful  
`piavpn-portforward.sh get_status`  
`piavpn-portforward.sh get_vpn_ip_address`  
`piavpn-portforward.sh get_public_ip_address`  




## rtorrent-functions.sh
No documentation yet.  this will configure rTorrent to pia vpn and also keep everything up to date as ports / ip's / connections change.