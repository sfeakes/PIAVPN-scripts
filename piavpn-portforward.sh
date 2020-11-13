#!/bin/bash

# ******************************************************************************************
#
#  Please modify the below variables to your setup
#
# ******************************************************************************************

VPN_INTERFACE="tun0"

CURL="/usr/bin/curl"
CURL_TIMEOUT=4
#IP="/usr/sbin/ip"
IP="/sbin/ip"
IFCONFIG="/sbin/ifconfig"
TRACEROUTE="/usr/sbin/traceroute"
JQ="/usr/bin/jq"
DIG="/usr/bin/dig"

# If you use a credentials file for openvpn, you can point to it here.
# if not comment `CREDENTIALS=`` uncomment the `PIA_USER=` & `PIA_PASS=` and set them appropiatly.
CREDENTIALS='/etc/openvpn/user.txt'
#PIA_USER=piauserxxxxxxx
#PIA_PASS=pispassxxxxxx

# There are sever ways to get your public ip address.
# using opendns, using google dns servers, or using ipinfo.io, set your predered below
# "opendns" "googledns" "ipinfo"
GET_PUBLIC_IP_METHOD="opendns"

# Where we store the cached PIA information. (this should be protected, it holds an auth key but not user/passwd)
PIA_INFO_FILE="/tmp/pia_vpn.info"

# ******************************************************************************************
#
#  You should not have to modify below this line
#
# ******************************************************************************************

if [ -f "$CREDENTIALS" ]; then
  PIA_USER=$(sed '1q;d' $CREDENTIALS 2>/dev/null)
  PIA_PASS=$(sed '2q;d' $CREDENTIALS 2>/dev/null)
fi

TRUE=0
FALSE=1

BAD_PORT="0"
BAD_IP="1.1.1.1"


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

  if [ "$GET_PUBLIC_IP_METHOD" == "googledns" ]; then
    publicIP=$($DIG dig TXT +short -b $(get_PIA_VPN_IP) o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"' )
  elif [ "$GET_PUBLIC_IP_METHOD" == "ipinfo" ]; then
    publicIP=$($CURL -s -m $CURL_TIMEOUT http://ipinfo.io/ip)
  else
    publicIP=$($DIG +short -b $(get_PIA_VPN_IP) myip.opendns.com @resolver1.opendns.com 2>/dev/null )
  fi

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

  $(umask 077; touch $PIA_INFO_FILE)
  echo "token:$pia_token" >> $PIA_INFO_FILE
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



function test_PIA_portforward() {
  if [ -f ${PIA_INFO_FILE} ]; then
    port=$(cat $PIA_INFO_FILE | grep 'port:' | cut -d: -f2)
    public_ip=$(cat $PIA_INFO_FILE | grep 'publicIP:' | cut -d: -f2)
  else
    echo $FALSE
    return $FALSE
  fi

  ext_status=$($CURL -s -X POST -d "remoteAddress=$public_ip&portNumber=$port" "https://ports.yougetsignal.com/check-port.php" | awk 'BEGIN { RS=" ";FS="\"" } /alt/{print $2}')

  if [ "$ext_status" == "Open" ]; then
    echo $TRUE
    return $TRUE
  fi

  echo $FALSE
  return $FALSE
}


# ******************************************************************************************
#
#  Main run functions
#
# ******************************************************************************************


function pia_status() {
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

  printf "%s\n" "------------------------------------------------"
  printf "%-12s | %-15s | %-15s\n" "Test" "PIA VPN" "System"
  printf "%s\n" "------------------------------------------------"
  
  vpn_running_test=$(is_VPN_up)
  printf "%-12s | %-15s | %-15s\n" "VPN Running" `if [ "$vpn_running_test" == "$TRUE" ];then echo Yes;else echo No;fi` "N/A"

  system_vpnip=$(get_PIA_VPN_IP)
  printf "%-12s | %-15s | %-15s\n" "VPN IP" "$pia_cache_vpnip" "$system_vpnip"

  system_publicip=$(get_public_IP)
  printf "%-12s | %-15s | %-15s\n" "Public IP" "$pia_cache_publicip" "$system_publicip"

  printf "%-12s | %-15s | %-15s\n" "Port forward" "$pia_cache_port" "N/A"

  external_port_test=$(test_PIA_portforward)
  port_bind_test=$(bind_PIA_portforward)
  printf "%-12s | %-15s | %-15s\n" "Ext Access" `if [ "$port_bind_test" == "$FALSE" ];then echo Failed;else echo Passed;fi` `if [ "$external_port_test" == "$FALSE" ];then echo Failed;else echo Passed; fi`
  printf "%s\n" "------------------------------------------------"
}


function recover_helper_error() {

  # Check VPN is up
  if [ "$(is_VPN_up)" == "$FALSE" ]; then
    error "VPN is down"
    echo $FALSE
    return $FALSE
  fi


  port=$(check_PIA_portfwd_cfg)
  if [ "$port" == "$FALSE" ]; then
    port=$(create_PIA_portforward)
    if [ "$port" == "$FALSE" ]; then
      error "Making PIA portforward call"
      echo $FALSE
      return $FALSE
    fi
  fi
  

  # Always want to bind port on this
  if port=$(bind_PIA_portforward); then
    rtn=$TRUE
  else
    rtn=$FALSE
  fi

  # This will reset return to bad ip or port 
  case $1 in
    get_public_ip_address)
      echo $(get_public_IP)
    ;;
    get_vpn_ip_address)
      echo $(get_PIA_VPN_IP)
    ;;
    *)
      echo $port
    ;;
  esac

  return $rtn;
}



# ******************************************************************************************
#
#  Main run
#
# ******************************************************************************************

if [[ $EUID -ne 0 ]]; then
  echo "$0 must be run as root, you are: `whoami`"
  if [ "$TERMINAL" == "$TRUE" ]; then
    sudo "$0" "$1" "$2"
  fi
  exit 1
fi


case $1 in
  check_install)
    output=""
    if ! command -v $CURL &>/dev/null; then output+="Please check 'curl' is installed\n"; fi
    if ! command -v $IP &>/dev/null; then output+="Please check 'ip' is installed\n"; fi
    if ! command -v $IFCONFIG &>/dev/null; then output+="Please check 'ifconfig' is installed\n"; fi
    if ! command -v $TRACEROUTE &>/dev/null; then output+="Please check 'traceroute' is installed\n"; fi
    if ! command -v $JQ &>/dev/null; then output+="Please check 'jq' is installed\n"; fi
    if ! command -v $DIG &>/dev/null; then output+="Please check 'dig' is installed\n"; fi
    if [ "$PIA_USER" == "" ]; then output+="Please set PIA_USER variable\n";fi
    if [ "$PIA_PASS" == "" ]; then output+="Please set PIA_PASS variable\n";fi
    if [ "$output" == "" ]; then
      echo "OK"
    else
      printf "Errors:-\n%b" "${output}"
    fi
    exit
  ;;
  get_public_ip_address)
    if ! rtn=$(check_PIA_portfwd_cfg) || ! ip=$(get_public_IP); then
      if ! ip=$(recover_helper_error "get_public_ip_address"); then
        error "get_public_ip_address"
        exit 1
      fi
    fi
    echo $ip
    exit 0
  ;;
  get_vpn_ip_address)
    if ! rtn=$(check_PIA_portfwd_cfg) || ! ip=$(get_PIA_VPN_IP); then
      if ! ip=$(recover_helper_error "get_vpn_ip_address"); then
        error "get_vpn_ip_address"
        exit 1
      fi
    fi
    echo $ip
    exit 0
  ;;
  get_public_port | bind_public_port)
    if ! rtn=$(check_PIA_portfwd_cfg) || ! port=$(bind_PIA_portforward); then
      if ! port=$(recover_helper_error "get_public_port"); then
        error "get_public_port"
        exit 1
      fi
    fi
    if [ "$1" == "get_public_port" ]; then
      echo "$port"
    fi
    exit 0
  ;;
  get_status)
    pia_status
    exit 0
  ;;
    
  *)
    if [ "$TERMINAL" == "$TRUE" ]; then
      echo "Call $0 with one of the following parameters (get_public_ip_address|get_vpn_ip_address|get_public_port|bind_public_port|get_status|check_install) "
    else
      log "missing parameter"
      exit 1
    fi
    exit 0
  ;;
esac 


exit

