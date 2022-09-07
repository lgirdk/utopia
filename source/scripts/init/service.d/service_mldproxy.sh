#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

#------------------------------------------------------------------
#------------------------------------------------------------------

source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/utctx_helper.sh

SERVICE_NAME="mldproxy"
SELF_NAME="`basename "$0"`"

BIN=mcproxy_v6
CONF_FILE=/tmp/mcproxy_v6.conf

wait_while_tentative() {
  local ifname=$1
  local i=0

  while [ $i -lt 10 ]; do
    i=$((i+1))
    awk -v ifname=$ifname '$6==ifname { flags="0x"$5; if (and(flags, 0x40)) exit 1; } ' /proc/net/if_inet6
    [ $? -eq 0 ] && break
    sleep 1
  done
}

do_start_mldproxy () {
   LOCAL_CONF_FILE=/tmp/mcproxy_v6.conf$$

   while pidof $BIN; do killall $BIN; sleep 1; done

   rm -rf $LOCAL_CONF_FILE

   #echo "fastleave" >> $LOCAL_CONF_FILE
   echo "protocol MLDv2;" >> $LOCAL_CONF_FILE
   if [ "started" = "$CURRENT_WAN_STATUS" ] ; then
      echo "pinstance v6Proxy: $WAN_IFNAME ==> $SYSCFG_lan_ifname;" >> $LOCAL_CONF_FILE
      echo "pinstance v6Proxy throttle $SYSCFG_igmp_mld_throttle_rate holdtime $SYSCFG_igmp_mld_throttle_holdtime;" >> $LOCAL_CONF_FILE
      if [ "$SYSCFG_igmp_mld_proxy_fastleave" = "0" ]; then
         echo "pinstance v6Proxy fastleave disable;" >> $LOCAL_CONF_FILE
      fi
      echo "pinstance v6Proxy downstream $SYSCFG_lan_ifname out whitelist table {(ff38::8000:0000 - ff38::ffff:ffff | *)};" >> $LOCAL_CONF_FILE
      echo "pinstance v6Proxy downstream $SYSCFG_lan_ifname in blacklist table {(* | *)};" >> $LOCAL_CONF_FILE
      echo "pinstance v6Proxy upstream $WAN_IFNAME in whitelist table {(ff38::8000:0000 - ff38::ffff:ffff | *)};" >> $LOCAL_CONF_FILE
      echo "pinstance v6Proxy upstream $WAN_IFNAME out blacklist table {(* | *)};" >> $LOCAL_CONF_FILE
   fi

#   Commenting brlan0 downstream from mldproxy config (RDKB-10413)
#   echo "phyint $SYSCFG_lan_ifname downstream" >> $LOCAL_CONF_FILE

   cat $LOCAL_CONF_FILE > $CONF_FILE
   rm -f $LOCAL_CONF_FILE 
   wait_while_tentative $SYSCFG_lan_ifname
   $BIN -r -f $CONF_FILE &
}

service_init ()
{
   queries="mldproxy_enabled lan_ifname last_erouter_mode dslite_enable igmp_mld_throttle_rate igmp_mld_throttle_holdtime igmp_mld_proxy_fastleave"
   get_utctx_val "$queries"
   eval `sysevent batchget current_wan_ifname wan-status lan-status`
   WAN_IFNAME=$SYSEVENT_1
   CURRENT_WAN_STATUS=$SYSEVENT_2
   CURRENT_LAN_STATUS=$SYSEVENT_3
}

service_start () 
{
   ulog ${SERVICE_NAME} status "starting ${SERVICE_NAME} service" 

   if [ -n "$WAN_IFNAME" ] && [ "1" == "$SYSCFG_mldproxy_enabled" ] && [ "$SYSCFG_dslite_enable" = "1" -o "$SYSCFG_last_erouter_mode" = "3" ] ; then
      do_start_mldproxy
      sysevent set ${SERVICE_NAME}-errinfo
      sysevent set ${SERVICE_NAME}-status "started"
   fi
}

service_stop () 
{
   ulog ${SERVICE_NAME} status "stopping ${SERVICE_NAME} service" 

   killall $BIN
   rm -rf $CONF_FILE

   sysevent set ${SERVICE_NAME}-errinfo
   sysevent set ${SERVICE_NAME}-status "stopped"
}

# Entry

service_init

case "$1" in
  "${SERVICE_NAME}-start")
      service_start
      ;;
  "${SERVICE_NAME}-stop")
      service_stop
      ;;
  "${SERVICE_NAME}-restart")
      service_stop
      service_start
      ;;
  wan-status)
      if [ "started" = "$CURRENT_WAN_STATUS" ] && [ "started" = "$CURRENT_LAN_STATUS" ] ; then
         service_start
      elif [ "stopped" = "$CURRENT_WAN_STATUS" ] || [ "stopped" = "$CURRENT_LAN_STATUS" ] ; then
         service_stop 
      fi
      ;;
  lan-status)
      if [ "started" = "$CURRENT_WAN_STATUS" ] && [ "started" = "$CURRENT_LAN_STATUS" ] ; then
         service_start
      elif [ "stopped" = "$CURRENT_WAN_STATUS" ] || [ "stopped" = "$CURRENT_LAN_STATUS" ] ; then
         service_stop 
      fi
      ;;
  *)
      echo "Usage: $SELF_NAME [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart | wan-status | lan-status ]" >&2
      exit 3
      ;;
esac
