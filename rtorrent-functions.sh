#!/bin/bash
TRUE=0
FALSE=1

#STOP_START_RTORRENT_ON_VPN_CONNECTION=$FALSE

PIA_INFO_FILE="/tmp/pia_vpn.info"
VPN_INTERFACE="tun0"

CURL="/usr/bin/curl"
CURL_TIMEOUT=4
IP="/usr/sbin/ip"
IFCONFIG="/sbin/ifconfig"
TRACEROUTE="/usr/sbin/traceroute"
JQ="/usr/bin/jq"
SYSTEMCTL="/usr/bin/systemctl"
DIG="/usr/bin/dig"
XMLRPC="/usr/bin/xmlrpc"
PGREP="/usr/bin/pgrep"

XMLRPC_CON="localhost:80/RPC2"

BAD_PORT="0"
BAD_IP="1.1.1.1"

START_VPN_CMD="$SYSTEMCTL start openvpn"
STOP_VPN_CMD="$SYSTEMCTL stop openvpn"
START_RTORNT_CMD="$SYSTEMCTL start rtorrent"
STOP_RTORNT_CMD="$SYSTEMCTL stop rtorrent"

CREDENTIALS='/etc/openvpn/user.txt'
# Since we don't always run this as root, can get error, so hide it.
PIA_USER=$(sed '1q;d' $CREDENTIALS 2>/dev/null)
PIA_PASS=$(sed '2q;d' $CREDENTIALS 2>/dev/null)


# This is used for pgrep only,  match rtorrent but not rtorrent_somecrap 
#TRP_REGEX="rtorrent .*"
TRP_REGEX="rtorrent .*|^rtorrent$"

# Below is used for install
BIN_DIR="/usr/bin"
LIB_DIR="/usr/lib/rtorrent-utils"
LIB_NAME="rtorrent-functions.sh"
LN_NAMES=("rtorrent_recondition" "rtorrent_status" "rtorrent_bindPIAport" "rtorrent_overview" "rtorrent_helper" "rtorrent_vpn_up" "rtorrent_vpn_down")

# ******************************************************************************************
#
# OTHER CONFIG ITEMS FOR THIS TO WORK
#
#  rtorrent cfg for this to work
# # `network.port_range.set` will not take effect unless `network.bind_address.set` is called after it.
# method.insert = get_vpn_ip_address, simple|private, "execute.capture=bash,-c,\"sudo /usr/bin/rtorrent_helper get_vpn_ip_address\""
# method.insert = get_public_port, simple|private, "execute.capture=bash,-c,\"sudo /usr/bin/rtorrent_helper get_public_port\""
# method.insert = get_public_ip_address, simple|private, "execute.capture=bash,-c,\"sudo /usr/bin/rtorrent_helper get_public_ip_address\""
# schedule2 = vpn_ip_tick, 3, 1800, "network.bind_address.set=(get_vpn_ip_address)"
# schedule2 = public_port_tick, 0, 900, "network.port_range.set=(get_public_port)"
# schedule2 = public_ip_tick, 2, 1800, "network.local_address.set=(get_public_ip_address)"
#
# put into openvpn config file for this to work
#
# script-security 2
# up /usr/bin/rtorrent_vpn_up
# down /usr/bin/rtorrent_vpn_down
#
# /etc/sudoers needs access to these scripts and systemctl
# sf,rtorrent,www-data 192.168.144.0/255.255.255.0=(root) NOPASSWD: /usr/lib/rtorrent-utils/*, /usr/sbin/traceroute, /usr/bin/systemctl
#
# Crontab also needs to be set
# # Run every hour
# 0 * * * * "/usr/bin/rtorrent_recondition"
#
# ******************************************************************************************
# 
#  Notes
#
#  use below to monitor port for traffic (ie check port forward)
#  sudo tcpdump -ni any port 53868
#
#  In rtorrent we use network.port_range for the incomming port, as it can be set and changed.
#  It may be better to use the port (network.listen.port) but as that can't be set even in config
#  we would need to use iptables to do portforwarding.  That may bring in other issues of 
#  network.bind_address which is currently vpn, might need to create a virtual netowrk interface.
#
# ******************************************************************************************

if [ -t 0 ]; then 
  TERMINAL=$TRUE
else
  TERMINAL=$FALSE
fi
# ******************************************************************************************
#
#  Helper functions
#
# ******************************************************************************************

function log() {
  if [ "$TERMINAL" == "$TRUE" ]; then
    logger -s $0" "$*
  else
    logger $0" "$*
  fi
}

function error() {
  #>&2 echo "Error: "$0" "$*
  if [ "$TERMINAL" == "$TRUE" ]; then
    logger -s "Error: "$0" "$*
  else
    logger "Error: "$0" "$*
  fi
}

# Print if we are in terminal, but print to stderror since stdout is for function returns
function term_print() {
  if [ "$TERMINAL" == "$TRUE" ]; then
    >&2 echo "$*"
  fi
}

function is_valid_ip() {
  if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo $TRUE
    return $TRUE
  else
    echo $FALSE
    return $FALSE
  fi
}

function get_PIA_VPN_IP() {
  #vpnIP=$($IFCONFIG $VPN_INTERFACE 2>/dev/null | grep "inet " | awk -F' ' '{print $2}')
  vpnIP=$($IP -o -4 a s $VPN_INTERFACE | awk -F"[ /]+" '{print $4}')
  
  if [ -z "$vpnIP" ]; then
    echo $BAD_IP
    return $FALSE
  fi

  if [ $(is_valid_ip $vpnIP) == "$FALSE" ]; then
    echo $BAD_IP
    return $FALSE
  fi

  echo $vpnIP
  return $TRUE

}

function get_PIA_portforward() {

  if [ -f ${PIA_INFO_FILE} ]; then
    port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
    echo $port
    return $TRUE
  fi

  echo $BAD_PORT
  return $FALSE
}

function get_public_IP() {
  # Google options would be dig TXT +short o-o.myaddr.l.google.com @ns1.google.com
  #publicIP=$($DIG dig TXT +short -b $(get_PIA_VPN_IP) o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"' )
  #publicIP=$($CURL -s -m $CURL_TIMEOUT http://ipinfo.io/ip)
  publicIP=$($DIG +short -b $(get_PIA_VPN_IP) myip.opendns.com @resolver1.opendns.com 2>/dev/null )

  if [ -z "$publicIP" ]; then
    echo $BAD_IP
    return $FALSE
  fi

  if [ $(is_valid_ip $publicIP) == "$FALSE" ]; then
    echo $BAD_IP
    return $FALSE
  fi

  echo $publicIP
  return $TRUE
}

function is_VPN_up()
{
  adapter_check=$( $IP a s $VPN_INTERFACE 2>&1 )
  
  if [ $? == 1 ]; then
    echo $FALSE
    return $FALSE
  fi
  if [[ "$adapter_check" == "Device \"$VPN_INTERFACE\" does not exist." ]]; then
    echo $FALSE
    return $FALSE
  fi

  if RTN=`sudo $TRACEROUTE -i $VPN_INTERFACE -m 1 nl.privateinternetaccess.com` ; then
    if echo "$RTN" | grep '\* \* \*' > /dev/null; then
      echo $FALSE
      return $FALSE
    fi
  else
    echo $FALSE
    return $FALSE
  fi

  echo $TRUE
  return $TRUE
}

function is_rTorrent_running()
{
  #if $PGREP -f $TR_BIN &>/dev/null ; then
  if $PGREP -f "$TRP_REGEX" &>/dev/null ; then
    echo $TRUE
    return $TRUE
  else
    echo $FALSE
    return $FALSE
  fi
}

function get_PIA_gateway()
{
  PIAgateway=$(ip route s t all | grep -m 1 "0.0.0.0/1 via .* dev ${VPN_INTERFACE}" | cut -d ' ' -f3)

  if [ -z "$PIAgateway" ]; then
    echo $BAD_IP
    return $FALSE
  fi

  echo $PIAgateway
  return $TRUE
}

function get_PIA_usertoken()
{
  generateTokenResponse=$(curl --interface "${VPN_INTERFACE}" --silent --insecure -u "${PIA_USER}:${PIA_PASS}" "https://10.0.0.1/authv3/generateToken")

  if [ "$(echo "$generateTokenResponse" | jq -r '.status')" != "OK" ]; then
    error "Could not get a PIA user token. Please check your account credentials."
    echo $FALSE
    return $FALSE
  fi

  pia_token="$(echo "$generateTokenResponse" | jq -r '.token')"

  if [ -z "$pia_token" ]; then
    echo $FALSE
    return $FALSE
  fi

  echo $pia_token
  return $TRUE
}

function create_PIA_portforward()
{
  pia_publicIP=$(get_public_IP)
  pia_token=$(get_PIA_usertoken)
  pia_gateway=$(get_PIA_gateway)
  pia_vpnIP=$(get_PIA_VPN_IP)

  #pia_token=$1
  #pia_gateway=$2
  #pia_vpnIP=$3
  #pia_publicIP=$4

  payload_and_signature=$($CURL --insecure --silent --max-time 5 --get --data-urlencode "token=${pia_token}" "https://${pia_gateway}:19999/getSignature")

  # Check if the payload and the signature are OK.
  # If they are not OK, just stop the script.
  if [ "$(echo "$payload_and_signature" | $JQ -r '.status')" != "OK" ]; then
    error "The payload_and_signature variable does not contain an OK status."
    error $payload_and_signature
    echo $FALSE
    return $FALSE;
  fi

  # We need to get the signature out of the previous response.
  # The signature will allow the us to bind the port on the server.
  signature="$(echo "$payload_and_signature" | $JQ -r '.signature')"

  # The payload has a base64 format. We need to extract it from the
  # previous response and also get the following information out:
  # - port: This is the port you got access to
  # - expires_at: this is the date+time when the port expires
  payload="$(echo "$payload_and_signature" | $JQ -r '.payload')"
  port="$(echo "$payload" | base64 -d | $JQ -r '.port')"

  # The port normally expires after 2 months. If you consider
  # 2 months is not enough for your setup, please open a ticket.
  expires_at="$(echo "$payload" | base64 -d | $JQ -r '.expires_at')"

  echo "token:$pia_token" > $PIA_INFO_FILE
  echo "gateway:$pia_gateway" >> $PIA_INFO_FILE
  echo "publicIP:$pia_publicIP"  >> $PIA_INFO_FILE
  echo "vpnIP:$pia_vpnIP"  >> $PIA_INFO_FILE
  echo "signature:$signature" >> $PIA_INFO_FILE
  echo "payload:$payload" >> $PIA_INFO_FILE
  echo "expires:$expires_at" >> $PIA_INFO_FILE
  echo "port:$port" >> $PIA_INFO_FILE

  echo $port
  return $TRUE
}

function check_PIA_portfwd_cfg() {
  # Not best check, all we can do is check file exists and token is out of date.
  if [ -f ${PIA_INFO_FILE} ]; then
    expires=$(cat $PIA_INFO_FILE | grep 'expires:' | cut -d: -f2,3,4,5)
    port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
    public_ip=$(cat $PIA_INFO_FILE | grep 'publicIP:' | cut -d: -f2)
    gateway=$(cat $PIA_INFO_FILE | grep 'gateway:' | cut -d: -f2)
    vpnip=$(cat $PIA_INFO_FILE | grep 'vpnIP:' | cut -d: -f2)
  else
    echo $FALSE
    return $FALSE
  fi

  if [ "$public_ip" != "`get_public_IP`" ]; then
    error "PIA External IP changed"
    echo $FALSE
    return $FALSE
  fi

  if [ "$gateway" != "`get_PIA_gateway`" ]; then
    error "PIA Gateway changed"
    echo $FALSE
    return $FALSE
  fi

  if [ "$vpnip" != "`get_PIA_VPN_IP`" ]; then
    error "PIA VPN IP changed"
    echo $FALSE
    return $FALSE
  fi

  # Should probably to 15 mins before time expires
  if [ $(date +"%s") -gt $(date --date "$expires" +"%s") ]; then
    error "PIA port forward token out of date"
    echo $FALSE
    return $FALSE
  fi

  echo $port
  return $TRUE
}

function bind_PIA_portforward() {

  if [ -f ${PIA_INFO_FILE} ]; then
    #token=$(cat $PIA_INFO_FILE | grep 'token:' | cut -d: -f2)
    gateway=$(cat $PIA_INFO_FILE | grep 'gateway:' | cut -d: -f2)
    signature=$(cat $PIA_INFO_FILE | grep 'signature:' | cut -d: -f2)
    payload=$(cat $PIA_INFO_FILE | grep 'payload:' | cut -d: -f2)
    port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
  else
    error "Error: $PIA_INFO_FILE doesn't exist"
    echo $FALSE
    return $FALSE
  fi

  bind_port_response=$($CURL --insecure --silent --max-time 5 --get --data-urlencode "payload=${payload}" --data-urlencode "signature=${signature}" "https://${gateway}:19999/bindPort")

  # Good replys are
  # { "status": "OK", "message": "port scheduled for add" }
  # { "status": "OK", "message": "timer refreshed" }

  #error "return $bind_port_response"

  if [ -z "$bind_port_response" ]; then
    echo $FALSE
    return $FALSE
  fi

  if [ "`echo "$bind_port_response" | $JQ -r '.status'`" != "OK" ]; then
    echo $FALSE
    return $FALSE
  fi
  
  echo $port
  return $TRUE
}

function get_bindIP_from_rtorrent() {
  bound_to=$(get_rtorrent_cfg_string "network.bind_address")
  echo $bound_to

  if [ "$bound_to" == "$FALSE" ]; then
    return $FALSE
  fi
  
  return $TRUE
}

function get_port_from_rtorrent() {
  port_forward=$(get_rtorrent_cfg_string "network.port_range")
  port_forward=$(echo $port_forward | sed -r 's|([0-9]*)-.*|\1|')
  echo $port_forward
  
  if [ "$port_forward" == "$FALSE" ]; then
    return $FALSE
  fi
  
  return $TRUE
}

function get_publicIP_from_rtorrent() {
  public_ip=$(get_rtorrent_cfg_string "network.local_address")
  echo $public_ip
  
  if [ "$public_ip" == "$FALSE" ]; then
    return $FALSE
  fi
  
  return $TRUE
}

function write_bindIP_to_rtorrent() {
  new_bind=$1
  current_bind=$(get_bindIP_from_rtorrent)
  
  if [ "$current_bind" != "$new_bind" ]; then
    rtn=$(set_rtorrent_cfg_string "network.bind_address.set" "$new_bind")
    echo $rtn
    return $rtn
  fi
  
  echo $TRUE
  return $TRUE
}

function write_port_to_rtorrent() {
  new_port=$1
  current_port=$(get_port_from_rtorrent)
  
  if [ "$current_port" != "$new_port" ]; then
    rtn=$(set_rtorrent_cfg_string "network.port_range.set" "$new_port-$new_port")
    echo $rtn
    return $rtn
  fi
  
  echo $TRUE
  return $TRUE
}

function write_publicIP_to_rtorrent() {
  new_public_ip=$1
  current_public_ip=$(get_bindIP_from_rtorrent)
  
  if [ "$current_public_ip" != "$new_public_ip" ]; then
    rtn=$(set_rtorrent_cfg_string "network.local_address.set" "$new_public_ip")
    echo $rtn
    return $rtn
  fi
  
  echo $TRUE
  return $TRUE
}


function test_PIA_portforward() {
  if [ -f ${PIA_INFO_FILE} ]; then
    port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
    public_ip=$(cat $PIA_INFO_FILE | grep 'publicIP:' | cut -d: -f2)
  else
    echo $FALSE
    return $FALSE
  fi

  #ext_status=$($CURL -s -m $CURL_TIMEOUT "http://feakes.cc/share/pc.php?p=$port")
  ext_status=$($CURL -s -X POST -d "remoteAddress=$public_ip&portNumber=$port" "https://ports.yougetsignal.com/check-port.php" | awk 'BEGIN { RS=" ";FS="\"" } /alt/{print $2}')

  if [ "$ext_status" == "Open" ]; then
    echo $TRUE
    return $TRUE
  fi

  echo $FALSE
  return $FALSE
}

function get_rtorrent_cfg_string() {
  
  string=$($XMLRPC $XMLRPC_CON $1 2>/dev/null | grep "String" | cut -d"'" -f2)

  if [ -z "$string" ]; then
    echo $FALSE;
    return $FALSE
  fi

  echo $string
  return $TRUE
}

function set_rtorrent_cfg_string() {
  
  #return=$($XMLRPC $XMLRPC_CON $1 "" $2 2>/dev/null | grep "Integer" | cut -d"'" -f2)
# Doesn;t always return Integer
# returns the above if it didn;t change
  return=$($XMLRPC $XMLRPC_CON $1 "" $2 2>/dev/null)

  if [[ -z "$return" || "$?" != "0" ]]; then
    #term_print "Return from $1 $2 = $return"
    echo $FALSE;
    return $FALSE
  fi

  echo $TRUE
  return $TRUE
}

# ******************************************************************************************
#
#  Main run functions
#
# ******************************************************************************************

function recondition_rTorrent() {

  # Check VPN
  if [ "$(is_VPN_up)" == "$FALSE" ]; then
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "VPN is" "Bad")"
    log "VPN is down, Restarting!"
    $STOP_VPN_CMD
    $START_VPN_CMD
    sleep 5
    
    # VPN Failed to start
    if [ "$(is_VPN_up)" == "$FALSE" ]; then
      if [ "$(is_rTorrent_running)" == "$TRUE" ]; then
        error "Restarting VPN failed!, stopping rtorrent"
        $STOP_RTORNT_CMD
      else
        error "Restarting VPN failed!"
      fi
      echo $FALSE
      return $FALSE
    fi
  else
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "VPN is" "Running")"
  fi

  #Check rTorrennt
  if [ "$(is_rTorrent_running)" == "$FALSE" ]; then
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "rTorrent is" "Bad")"
    log "rTorrent is down, Starting!"
    #$STOP_RTORNT_CMD
    $START_RTORNT_CMD
    sleep 5
    if [ "$(is_rTorrent_running)" == "$FALSE" ]; then
      error "Restarting rTorrent failed!"
      echo $FALSE
      return $FALSE
    fi
  else
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "rTorrent is" "Running")"
  fi


  #if [ "$(check_PIA_portfwd_cfg)" == "$FALSE" ]; then
  #  term_print "$(printf "%-21s %8s : \033[1m%-16s\033[0m" "PIA Port Forward" "$(check_PIA_portfwd_cfg)" "Bad")"
  if ! port=$(check_PIA_portfwd_cfg); then
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Port Forward" "$port" "Bad")"
    log "PIA Port Forward configuration is bad, resetting"
    port=$(create_PIA_portforward)
    if [ "$port" == "$FALSE" ]; then
      error "Making PIA portforward call"
      echo $FALSE
      return $FALSE
    fi
  else
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Port Forward" "$port" "Good")"
  fi

  # Always want to bind port on this
  if [ "$(bind_PIA_portforward)" == "$FALSE" ]; then
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Bind to port" "$(get_PIA_portforward)" "Failed")"
    echo $FALSE
    return $FALSE
  else
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Bind to port" "$(get_PIA_portforward)" "Passed")"
  fi

  # write_bindIP_to_rtorrent MUST be called after write_port_to_rtorrent, so stuck with this order
  if [ $(get_PIA_portforward) != "$(get_port_from_rtorrent)" ]; then
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "rTorrent port forward" "$(get_PIA_portforward)" "Bad")"
    log "rTorrent config Port is incorrect, $(get_PIA_portforward) vs $(get_port_from_rtorrent)"
    if [ "$(write_port_to_rtorrent $(get_PIA_portforward) )" == "$FALSE" ]; then
      error "updating rTorrent config Port failed"
      echo $FALSE
      return $FALSE
    else
      term_print "Updated rTorrent Port"
    fi
  else
    term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "rTorrent port forward" "$(get_PIA_portforward)" "Good")"
  fi

  if [ $(get_PIA_VPN_IP) != "$(get_bindIP_from_rtorrent)" ]; then
    term_print "$(printf "%-17s %15s : \033[1m%-16s\033[0m" "rTorrent VPN IP" "$(get_PIA_VPN_IP)" "Bad")"
    log "rTorrent config bindIP is incorrect"
    if [ "$(write_bindIP_to_rtorrent $(get_PIA_VPN_IP) )" == "$FALSE" ]; then
      error "updating rTorrent config bindIP failed"
      echo $FALSE
      return $FALSE
    else
      term_print "Updated rTorrent bindIP"
    fi
  else
    term_print "$(printf "%-17s %15s : \033[1m%-16s\033[0m" "rTorrent VPN IP" "$(get_PIA_VPN_IP)" "Good")"
  fi

  

  if [ $(get_public_IP) != "$(get_publicIP_from_rtorrent)" ]; then
    term_print "$(printf "%-17s %15s : \033[1m%-16s\033[0m" "rTorrent PublicIP" "$(get_public_IP)" "Bad")"
    log "rTorrent config PublicIP is incorrect"
    if [ "$(write_publicIP_to_rtorrent $(get_public_IP) )" == "$FALSE" ]; then
      error "updating rTorrent config PublicIP failed"
      echo $FALSE
      return $FALSE
    else
      term_print "Updated rTorrent PublicIP"
    fi
  else
    term_print "$(printf "%-17s %15s : \033[1m%-16s\033[0m" "rTorrent PublicIP" "$(get_public_IP)" "Good")"
  fi

  # Always want to bind port on this
  #if [ "$(bind_PIA_portforward)" == "$FALSE" ]; then
  #  term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Bind to port" "$(get_PIA_portforward)" "Failed")"
  #  echo $FALSE
  #  return $FALSE
  #else
  #  term_print "$(printf "%-24s %8s : \033[1m%-16s\033[0m" "PIA Bind to port" "$(get_PIA_portforward)" "Passed")"
  #fi

  if [ "$(test_PIA_portforward)" == "$FALSE" ]; then
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "rTorrent incomming connections" "Failed")"
  else
    term_print "$(printf "%-33s : \033[1m%-16s\033[0m" "rTorrent incomming connections" "Passed")"
  fi

  echo $TRUE
  return $TRUE
}

function status_rTorrent() {
  status=$TRUE

  if [ -f ${PIA_INFO_FILE} ]; then
    pia_cache_expires=$(cat $PIA_INFO_FILE | grep 'expires:' | cut -d: -f2)
    pia_cache_port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
    pia_cache_publicip=$(cat $PIA_INFO_FILE | grep 'publicIP:' | cut -d: -f2)
    pia_cache_vpnip=$(cat $PIA_INFO_FILE | grep 'vpnIP:' | cut -d: -f2)
  else
    status=$FALSE
    pia_cache_port=$BAD_IP
    pia_cache_publicip=$BAD_IP
    pia_cache_vpnip=$BAD_IP
  fi

  if [ "$1" != "json" ]; then
    term_print '---------------------------------------------------------------'
    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "Test" "PIA VPN" "System" "rTorrent" )"
    term_print '---------------------------------------------------------------'

    vpn_running_test=$(is_VPN_up)
    tor_running_test=$(is_rTorrent_running)
    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "Running" `if [ "$vpn_running_test" == "$TRUE" ];then echo Yes;else echo No;fi` "N/A" `if [ "$tor_running_test" == "$TRUE" ];then echo Yes;else echo No;fi` )"

    system_vpnip=$(get_PIA_VPN_IP)
    torrent_vpnip=$(get_bindIP_from_rtorrent)
    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "VPN IP" "$pia_cache_vpnip" "$system_vpnip" "$torrent_vpnip" )"

    system_publicip=$(get_public_IP)
    torrent_publicip=$(get_publicIP_from_rtorrent)
    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "Public IP" "$pia_cache_publicip" "$system_publicip" "$torrent_publicip" )"

    torrent_port=$(get_port_from_rtorrent)
    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "Port forward" "$pia_cache_port" "N/A" "$torrent_port" )"
  
    external_port_test=$(test_PIA_portforward)
    port_bind_test=$(bind_PIA_portforward)

    term_print "$(printf "%-12s | %-15s | %-15s | %-15s" "Ext Access" `if [ "$port_bind_test" == "$FALSE" ];then echo Failed;else echo Passed;fi` "N/A" `if [ "$external_port_test" == "$FALSE" ];then echo Failed;else echo Passed; fi` )"
    term_print '---------------------------------------------------------------'
  else
     # These are duplicate of above, but here to control json output
    vpn_running_test=$(is_VPN_up)
    tor_running_test=$(is_rTorrent_running)
    system_vpnip=$(get_PIA_VPN_IP)
    torrent_vpnip=$(get_bindIP_from_rtorrent)
    system_publicip=$(get_public_IP)
    torrent_publicip=$(get_publicIP_from_rtorrent)
    torrent_port=$(get_port_from_rtorrent)
    external_port_test=$(test_PIA_portforward)
    port_bind_test=$(bind_PIA_portforward)
  fi #JSON format


  if [ "$vpn_running_test" == "$FALSE" ]; then
    error "VPN is down"
    status=$FALSE
  fi

  if [ "$tor_running_test" == "$FALSE" ]; then
    error "rTorrent is not runing"
    status=$FALSE
  fi

  if [[ "$pia_cache_publicip" != "$system_publicip"  || "$system_publicip" != "$torrent_publicip" ]]; then
    error "Public IP test bad"
    status=$FALSE
  fi

  if [[ "$pia_cache_vpnip" != "$system_vpnip"  || "$system_vpnip" != "$torrent_vpnip" ]]; then
    error "VPN IP test bad"
    status=$FALSE
  fi

  if [[ "$pia_cache_port" != "$torrent_port"  || "$port_bind_test" == "$FALSE" ||  "$external_port_test" == "$FALSE" ]]; then
    error "VPN Port test bad"
    status=$FALSE
  fi

  if [ $(check_PIA_portfwd_cfg) == "$FALSE" ]; then
    # That will print error, so no need
    status=$FALSE
  fi

  if [ "$1" = "json" ]; then
    if [ "$vpn_running_test" == "$TRUE" ]; then
      vpn_status="Up"
    else
      vpn_status="Down"
    fi
    if [ "$tor_running_test" == "$TRUE" ]; then
      tor_status="Up"
    else
      tor_status="Down"
    fi
    if [ "$status" == "$TRUE" ]; then
      ext_status="Good"
    else
      ext_status="Bad"
    fi
    echo "{ \"vpnstatus\":\"$vpn_status\"," \
           "\"torstatus\":\"$tor_status\"," \
           "\"vpnip\":\"$pia_cache_vpnip\"," \
           "\"vpnport\":\"$pia_cache_port\"," \
           "\"cfgip\":\"$torrent_vpnip\"," \
           "\"cfgport\":\"$torrent_port\"," \
           "\"extip\":\"$torrent_publicip\"," \
           "\"extport\":\"$torrent_port\"," \
           "\"extaccesstest\":\"$ext_status\" }"
  else
    if [ "$status" == "$FALSE" ]; then
      term_print '---------------------------------------------------------------'
    fi
  fi
  
  return $status
}

function overview_rTorrent() {
  json=$($CURL -s -m $CURL_TIMEOUT "http://localhost/?t=torrentstats")

  if [ "$1" = "json" ]; then
    echo $json
    return
  fi

  total_torrents="$(echo "$json" | $JQ -r '.total_torrents')"
  upload_speed_kB="$(echo "$json" | $JQ -r '.upload_speed_kB')"
  download_speed_kB="$(echo "$json" | $JQ -r '.download_speed_kB')"
  size_TB="$(echo "$json" | $JQ -r '.size_TB')"
  inerror="$(echo "$json" | $JQ -r '.inerror')"
  active_torrents="$(echo "$json" | $JQ -r '.active_torrents')"
  peers_connected="$(echo "$json" | $JQ -r '.peers_connected')"

  if [ "$1" = "pp" ]; then
    printf "  \033[1m%-17s \033[0m%-16s \033[1m%-17s \033[0m%-16s\n" "Up:" "$upload_speed_kB kB/s" "Down:" "$download_speed_kB kB/s"
    printf "  \033[1m%-17s \033[0m%-16s \033[1m%-17s \033[0m%-16s\n" "Active:" $active_torrents "Peers:" $peers_connected
    printf "  \033[1m%-17s \033[0m%-16s \033[1m%-17s \033[0m%-16s\n" "Total:" $total_torrents "Size:" "$size_TB TB"
  else
    echo "Total up: $upload_speed_kB kB/s"
    echo "Total down: $download_speed_kB kB/s"
    echo "Total Active: $active_torrents"
    echo "Total in error: $inerror"
    echo "Peers connected: $peers_connected"
    echo "Total: $total_torrents"
    echo "Total size: $size_TB TB"
  fi
}

function install() {

  if [ "$1" == "dev" ]; then
    for i in ${!LN_NAMES[@]}; do
      if [ ! -L "./${LN_NAMES[$i]}" ] ; then
        ln -s "$0" "./${LN_NAMES[$i]}"
      fi
    done
    return
  fi

  if [ ! -d "$LIB_DIR" ]; then
    mkdir "$LIB_DIR"
  fi

  cp "$0" "$LIB_DIR/$LIB_NAME"

  for i in ${!LN_NAMES[@]}; do
    if [ ! -L "$LIB_DIR/${LN_NAMES[$i]}" ] ; then
      ln -s "$LIB_DIR/$LIB_NAME" "$LIB_DIR/${LN_NAMES[$i]}"
    fi

    if [ ! -L "$BIN_DIR/${LN_NAMES[$i]}" ] ; then
      ln -s "$LIB_DIR/${LN_NAMES[$i]}" "$BIN_DIR/${LN_NAMES[$i]}"
    fi
  done

  term_print "$0 installed! the following commands are now available"
  for i in ${!LN_NAMES[@]}; do
    term_print "$BIN_DIR/${LN_NAMES[$i]}"
  done
}

function vpn_call_rTorrent() {


  bindIP = $BAD_IP
  pubIP = $BAD_IP
  port = $BAD_PORT

  # is up, get new information.
  if [ "$1" == "up" ]; then
    # chances are this is all changed, but chack first.
    if ! port=$(check_PIA_portfwd_cfg); then
      if ! port=$(create_PIA_portforward); then
        error "Making PIA portforward call"
        echo $FALSE
        return $FALSE
      fi
      if [ -f ${PIA_INFO_FILE} ]; then
        port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
        pubIP=$(cat $PIA_INFO_FILE | grep 'publicIP:' | cut -d: -f2)
        bindIP=$(cat $PIA_INFO_FILE | grep 'vpnIP:' | cut -d: -f2)
      else
        error "Reading PIA cache file"
        echo $FALSE
        return $FALSE
      fi
    fi
  fi


  if [ "$(is_rTorrent_running)" == "$FALSE" ]; then
    # No point in doing anything, probably got here from VPN starting on boot
    # before torrent is running, so let torrent start and sort it's own config out
    return;
  fi

  # if VPN is down, we want to write null info to rTorrent
  # so still write the bad_xx values.
  rtn=$TRUE

  if [ "$(write_bindIP_to_rtorrent $(bindIP) )" == "$FALSE" ]; then
    error "write_bindIP_to_rtorrent"
    rtn=$FALSE
  fi
  if [ "$(write_port_to_rtorrent $(port) )" == "$FALSE" ]; then
    error "write_port_to_rtorrent"
    rtn=$FALSE
  fi
  if [ "$(write_publicIP_to_rtorrent $(pubIP) )" == "$FALSE" ]; then
    error "write_publicIP_to_rtorrent"
    rtn=$FALSE
  fi

  echo $rtn
  return $rtn
}

function recover_helper_error() {

  continue=$TRUE
  # Check VPN is up
  if [ "$(is_VPN_up)" == "$FALSE" ]; then
    error "VPN is down, Restarting!"
    $STOP_VPN_CMD
    $START_VPN_CMD
    sleep 2
    if [ "$(is_VPN_up)" == "$FALSE" ]; then
      error "VPN restart failed!"
      rtn=$FALSE
      return
    fi
  fi

  if [ "$continue" == "$TRUE" ]; then
    port=$(check_PIA_portfwd_cfg)
    if [ "$port" == "$FALSE" ]; then
      port=$(create_PIA_portforward)
      if [ "$port" == "$FALSE" ]; then
        error "Making PIA portforward call"
        rtn=$FALSE
      fi
    fi
  fi

  # Always want to bind port on this
  if [ "$continue" == "$TRUE" ]; then
    port=$(bind_PIA_portforward)
  fi

  # This will reset return to bad ip or port 
  case $1 in
    get_public_ip_address)
      echo $(get_public_IP)
    ;;
    get_vpn_ip_address)
      echo $(get_PIA_VPN_IP)
    ;;
    get_public_port)
      echo $(bind_PIA_portforward)
    ;;
  esac
}

# ******************************************************************************************
#
#  Main run
#
# ******************************************************************************************


if [ "$1" == "install_dev" ]; then
  install "dev"
  exit
fi


if [[ $EUID -ne 0 ]]; then
   case `basename $0` in
   *rtorrent_overview*)
     # We don;t need root access for this.
   ;;
   *)
     echo "$0 must be run as root, you are: `whoami`"
     if [ "$TERMINAL" == "$TRUE" ]; then
       sudo "$0" "$1" "$2"
     fi
     exit $FALSE
   ;;
   esac
fi

if [ "$1" == "install" ]; then
  install
  exit
fi

case `basename $0` in
  *rtorrent_recondition*)
    exit $(recondition_rTorrent)
  ;;
  *rtorrent_status*)
    status_rTorrent $1
  ;;
  *rtorrent_bindPIAport*)
    exit $(bind_PIA_portforward)
  ;;
  *rtorrent_overview*)
    overview_rTorrent $1
  ;;
  *rtorrent_vpn_up*)
    exit $(vpn_call_rTorrent "up")
  ;;
  *rtorrent_vpn_down*)
    exit $(vpn_call_rTorrent "down")
  ;;
  *rtorrent_helper*)
    case $1 in
      get_public_ip_address)
        if ! rtn=$(check_PIA_portfwd_cfg) || ! ip=$(get_public_IP); then
          if ! ip=$(recover_helper_error "get_public_ip_address"); then
            error "get_public_ip_address"
            ip=$BAD_IP
          fi
        fi
        echo -n $ip
        exit 0
      ;;
      get_vpn_ip_address)
        if ! rtn=$(check_PIA_portfwd_cfg) || ! ip=$(get_PIA_VPN_IP); then
          if ! ip=$(recover_helper_error "get_vpn_ip_address"); then
            error "get_vpn_ip_address"
            ip=$BAD_IP
          fi
        fi
        echo -n $ip
        exit 0
      ;;
      get_public_port)
        if ! rtn=$(check_PIA_portfwd_cfg) || ! port=$(bind_PIA_portforward); then
        #if ! rtn=$(check_PIA_portfwd_cfg) ; then
        #if ! port=$(bind_PIA_portforward) ; then
          if ! port=$(recover_helper_error "get_public_port"); then
            error "get_public_port"
            port=$BAD_PORT
          fi
        fi
        echo -n "$port-$port"
        exit 0
      ;;
      get_rtorrent_config)
        echo "rTorrent is : `if is_rTorrent_running > /dev/null; then echo Running; else echo Stopped; fi`"
        echo "Public IP   : $(get_rtorrent_cfg_string 'network.local_address')"
        echo "Public Port : $(get_rtorrent_cfg_string 'network.port_range')"
        echo "VPN IP      : $(get_rtorrent_cfg_string 'network.bind_address')"
      ;;
      *)
        echo "Parameter '$1' is invalid"
      ;;
    esac
    exit
  ;;
  *)
    # Code should never get here but justincase files renamed
    log "Incorrect script name called ${0}"
    echo -n "Incorrect script name called ${0}, link to script with filename(s) | "
    for i in ${!LN_NAMES[@]}; do
      echo -n "${LN_NAMES[$i]} | "
    done
    echo ""
  ;;
esac 


exit


# xmlrpc localhost:80/RPC2 system.listMethods
# xmlrpc localhost:80/RPC2 network.bind_address
# below multicall examples
# http://xmlrpc-c.sourceforge.net/doc/xmlrpc.html