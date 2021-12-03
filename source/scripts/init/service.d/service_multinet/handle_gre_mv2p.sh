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
# ENTRY
#------------------------------------------------------------------

TYPE=Gre

GRE_IFNAME="gretap0"
GRE_IFNAME_DUMMY="gretap_0"
recover="false"
hotspot_down_notification="false"

source /etc/utopia/service.d/ut_plat.sh
source /etc/utopia/service.d/log_capture_path.sh
. /etc/device.properties
THIS=/etc/utopia/service.d/service_multinet/handle_gre.sh

MTU_VAL=1400
MSS_VAL=1378

GRE_PSM_BASE=dmsb.cisco.gre
#HS_PSM_BASE=dmsb.hotspot.gre
HS_PSM_BASE=dmsb.hotspot.tunnel
GRE_OBJ_GRE=dmsb.hotspot
GRE_PSM_NAME=name
#format for below is comma delimited FQDM
GRE_PSM_BRIDGES=AssociatedBridges 
#GRE_PSM_KAINT=KeepAlive.Interval
GRE_PSM_KAINT=RemoteEndpointHealthCheckPingInterval
#GRE_PSM_KAFINT=KeepAlive.FailInterval
GRE_PSM_KAFINT=RemoteEndpointHealthCheckPingIntervalInFailure
#GRE_PSM_KARECON=ReconnPrimary
GRE_PSM_KARECON=ReconnectToPrimaryRemoteEndpoint
#GRE_PSM_KATHRESH=KeepAlive.Threshold
GRE_PSM_KATHRESH=RemoteEndpointHealthCheckPingFailThreshold
#GRE_PSM_KAPOLICY=KeepAlive.Policy
GRE_PSM_KAPOLICY=KeepAlivePolicy
GRE_PSM_TOS=tos
GRE_PSM_KEY=key
GRE_PSM_CSUM=csumenabled
GRE_PSM_SEQ=seqnumenabled
#GRE_PSM_ENDPOINTS=Endpoints 
GRE_PSM_PRIENDPOINTS=PrimaryRemoteEndpoint
GRE_PSM_SECENDPOINTS=SecondaryRemoteEndpoint
GRE_PSM_ENDPOINT=endpoint
GRE_PSM_NUMBER_OF_EP=NumberOfEndPoints
#GRE_PSM_KACOUNT=KeepAlive.Count
GRE_PSM_KACOUNT=RemoteEndpointHealthCheckPingCount
#GRE_PSM_SNOOPCIRC=DHCP.CircuitIDSSID
GRE_PSM_SNOOPCIRC=EnableCircuitID
#GRE_PSM_SNOOPREM=DHCP.RemoteID
GRE_PSM_SNOOPREM=EnableRemoteID
GRE_PSM_SNOOP_OPTION60=EnableVendorClassID
GRE_PSM_ENABLE=enable
HS_PSM_ENABLE=Enable
GRE_PSM_LOCALIFS=LocalInterfaces   
GRE_PSM_TCPMSS=GreTcpMss
WIFI_PSM_PREFIX=eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.SSID
WIFI_RADIO_INDEX=RadioIndex

GRE_ARP_PROC=hotspot_arpd
HOTSPOT_COMP=CcspHotspot
ARP_NFQUEUE=0

WAN_IF=erouter0

TUNNEL_TYPE_GRE="gretap"

AB_SSID_DELIM=':'
AB_DELIM=","

BASEQUEUE=1

init_snooper_sysevents () {
    if [ x1 = x$SNOOP_CIRCUIT ]; then
        sysevent set snooper-circuit-enable 1
    else
        sysevent set snooper-circuit-enable 0
    fi
    
    if [ x1 = x$SNOOP_REMOTE ]; then
        sysevent set snooper-remote-enable 1
    else
        sysevent set snooper-remote-enable 0
    fi

    if [ x1 = x$SNOOP_OPTION60 ]; then
        sysevent set snooper-option60-enable 1
    else
        sysevent set snooper-option60-enable 0
    fi
}

read_greInst()
{
    inst=1
    count=0
    eval `psmcli get -e BRIDGE_INST_1 $HS_PSM_BASE.${inst}.interface.1.$GRE_PSM_BRIDGES`
    brinst=`echo $BRIDGE_INST_1 |cut -d . -f 4`
    sysevent set multinet-start $brinst
}


#args: remote endpoint, gre tunnel ifname
create_tunnel () {
    REMOTE_ENDPOINT=$1
    echo "Creating tunnel... remote:$REMOTE_ENDPOINT"


    NUMOF_COLON=`echo $REMOTE_ENDPOINT |  grep -o "\:" | wc -l`
    NUMOF_POINTS=`echo $REMOTE_ENDPOINT |  grep -o "\." | wc -l`

    if [ $NUMOF_COLON -gt 2 ] && [ $NUMOF_POINTS -eq 0 ]
    then
        TUNNEL_TYPE_GRE="ip6gretap"
    fi

    read_tunnel_params $2
    
    local extra=""
    if [ x1 = x$CSUM ]; then
        extra="csum"
    fi
    
    if [ x != x$KEY ]; then
        extra="$extra key $KEY"
    fi
    
    if [ x != x$TOS ]; then
        extra="$extra dsfield $TOS"
    fi
    
    WAN_IF=`sysevent get current_wan_ifname`
    
    isgretap0Present=`ip link show | grep gretap0`
    if [ -n "$isgretap0Present" ]; then
        echo "gretap0 is already present rename it before creating"
        ip link set dev $GRE_IFNAME name $GRE_IFNAME_DUMMY
    fi

    if [ "$TUNNEL_TYPE_GRE" = "gretap" ] ; then
        WAN_IP_ADDR=`sysevent get current_wan_ipaddr`
        ip link add $GRE_IFNAME type gretap remote ${REMOTE_ENDPOINT} local ${WAN_IP_ADDR} dev $WAN_IF $extra nopmtudisc
    else
        #ipv6
        WAN_IP_ADDR=`sysevent get wan6_ipaddr`
        ip link add $GRE_IFNAME type $TUNNEL_TYPE_GRE remote ${REMOTE_ENDPOINT} local ${WAN_IP_ADDR} dev $WAN_IF $extra encaplimit none
    fi

    ip link set up dev $GRE_IFNAME
    #add gre interface to harware accleration 
    echo "inf add $GRE_IFNAME" > /proc/driver/flowmgr/cmd

    sysevent set gre_current_endpoint $1
    sysevent set if_${2}-status $IF_READY
}

destroy_tunnel () {
    echo "Destroying tunnel... remote"

    ip link del $1
    echo "inf del $1" > /proc/driver/flowmgr/cmd
    sysevent set gre_current_endpoint
    sysevent set if_${1}-status $IF_DOWN
}

gre_preproc () {
    allGreInst="`psmcli getallinst $GRE_PSM_BASE.`"
    query=""
    
    # TODO break 1 to 1 dependence on instance numbers (hotspot and gre interface)
    for i in $allGreInst; do 
        query="$query GRE_$i $GRE_PSM_BASE.$i.$GRE_PSM_NAME"
    done
    
    eval `psmcli get -e $query`
    
    for i in $allGreInst; do
        eval sysevent set gre_\${GRE_${i}}_inst $i
    done
}

init_keepalive_sysevents () {
    keepalive_args="-n `sysevent get wan_ifname`"
    if [ x = x`sysevent get hotspotfd-primary` ]; then
        sysevent set hotspotfd-primary $PRIMARY
    fi
    
    if [ x = x`sysevent get hotspotfd-secondary` ]; then
        sysevent set hotspotfd-secondary $SECONDARY
    fi

    if [ x = x`sysevent get hotspotfd-ep-count` ]; then
        sysevent set hotspotfd-ep-count $NUMBER_OF_EP
    fi

    if [ x = x`sysevent get hotspotfd-threshold` ]; then
        sysevent set hotspotfd-threshold $KA_THRESH
    fi
    
    if [ x = x`sysevent get hotspotfd-keep-alive` ]; then
        sysevent set hotspotfd-keep-alive $KA_INTERVAL
    fi
    
    if [ x = x`sysevent get hotspotfd-max-secondary` ]; then
        sysevent set hotspotfd-max-secondary $KA_RECON_PRIM
    fi
    
    if [ x = x`sysevent get hotspotfd-policy` ]; then
        sysevent set hotspotfd-policy $KA_POLICY
    fi
    
    if [ x = x`sysevent get hotspotfd-count` ]; then
        sysevent set hotspotfd-count $KA_COUNT
    fi
    
    if [ x = x`sysevent get hotspotfd-dead-interval` ]; then
        sysevent set hotspotfd-dead-interval $KA_FAIL_INTERVAL
    fi
    
    if [ x"started" = x`sysevent get wan-status` ]; then
        sysevent set hotspotfd-enable 1
        keepalive_args="$keepalive_args -e 1"
    else
        sysevent set hotspotfd-enable 0
    fi
    
    sysevent set hotspotfd-log-enable 1
    
}

bInst_to_bNames () {
    BRIDGES=""
    local binst=""
    local query=""
    local num=0
    local num2=0
    OLD_IFS="$IFS"

    IFS="$AB_SSID_DELIM"
    for x in $2; do
        num=`expr $num + 1`
        IFS="$AB_DELIM"
        for i in $x; do
            num2=`expr $num2 + 1`
#            binst=`echo $i |cut -d . -f 4`
            query="$query WECBB_${num}_${num2} $NET_IDS_DM.$i.$NET_IFNAME"
            eval WECBB_${num}=\"\${WECBB_${num}} \"\'\$WECBB_\'${num}'_'${num2}
        done
        IFS="$AB_SSID_DELIM"
#        eval BRIDGE_$num=\$AB_SSID_DELIM
    done

    num=0
    IFS="$AB_DELIM"
    for i in $1; do
        num=`expr $num + 1`
        binst=`echo $i |cut -d . -f 4`
        query="$query BRIDGE_$num $NET_IDS_DM.$binst.$NET_IFNAME"
    done
    IFS="$OLD_IFS"

    if [ x != x"$query" ]; then
        eval `eval psmcli get -e $query`
    fi


    for i in `seq $num`; do
        eval eval BRIDGES=\\\"\\\$BRIDGES \${BRIDGE_${i}} \${WECBB_${i}} \\\$AB_SSID_DELIM \\\"
    done
}

read_init_params () {
	gre_preproc

    inst=$1

    eval `psmcli get -e PRIMARY $HS_PSM_BASE.${inst}.$GRE_PSM_PRIENDPOINTS SECONDARY $HS_PSM_BASE.${inst}.$GRE_PSM_SECENDPOINTS NUMBER_OF_EP $HS_PSM_BASE.${inst}.$GRE_PSM_NUMBER_OF_EP BRIDGE_INST_1 $HS_PSM_BASE.${inst}.interface.1.$GRE_PSM_BRIDGES BRIDGE_INST_2 $HS_PSM_BASE.${inst}.interface.2.$GRE_PSM_BRIDGES KA_INTERVAL $GRE_OBJ_GRE.$GRE_PSM_KAINT KA_FAIL_INTERVAL $GRE_OBJ_GRE.$GRE_PSM_KAFINT KA_POLICY $HS_PSM_BASE.${inst}.$GRE_PSM_KAPOLICY KA_THRESH $HS_PSM_BASE.${inst}.$GRE_PSM_KATHRESH KA_COUNT $HS_PSM_BASE.${inst}.$GRE_PSM_KACOUNT KA_RECON_PRIM $HS_PSM_BASE.${inst}.$GRE_PSM_KARECON SNOOP_CIRCUIT $HS_PSM_BASE.${inst}.$GRE_PSM_SNOOPCIRC SNOOP_REMOTE $HS_PSM_BASE.${inst}.$GRE_PSM_SNOOPREM`

    eval `psmcli get -e MSS_VAL $HS_PSM_BASE.${inst}.$GRE_PSM_TCPMSS`
    eval `psmcli get -e SNOOP_OPTION60 $HS_PSM_BASE.${inst}.$GRE_PSM_SNOOP_OPTION60`

    status=$?
    if [ "$status" != "0" ]
    then
        echo "WARNING: handle_gre.sh read_init_params: psmcli return $status"
    fi
    echo "PRIMARY $PRIMARY SECONDARY $SECONDARY"
    if [ -z "$PRIMARY" ] || [ -z "$SECONDARY" ]
    then
        echo "WARNING: handle_gre.sh read_init_params: PRIMARY/SECONDARY NULL"
    fi
    if [ -z "$KA_INTERVAL" ]
    then
        echo "WARNING: handle_gre.sh read_init_params: KA_INTERVAL NULL"
    fi

    BRIDGE_INSTS="$BRIDGE_INST_1 $BRIDGE_INST_2"
    bInst_to_bNames "$BRIDGE_INSTS"
}

read_tunnel_params () {
    inst=`sysevent get gre_$1_inst`
    eval `psmcli get -e KEY $GRE_PSM_BASE.${inst}.$GRE_PSM_KEY CSUM $GRE_PSM_BASE.${inst}.$GRE_PSM_CSUM TOS $GRE_PSM_BASE.${inst}.$GRE_PSM_TOS`
}

#args: gre ifname
update_bridge_config () {
    inst=`sysevent get gre_$1_inst`
    curBridges="`sysevent get gre_${inst}_current_bridges`"

    if [ x != x"$curBridges" ]; then
        remove_bridge_config ${inst} "$curBridges"
    fi
    echo 0x100 > /proc/sys/net/bridge/bridge-nf-call-iptables-mark

    queue=$BASEQUEUE
    for br in $BRIDGES; do
        if [ "$AB_SSID_DELIM" = $br ]; then
            queue=`expr $queue + 1`
            continue
        fi
        br_snoop_rule="`sysevent setunique GeneralPurposeFirewallRule " -A FORWARD -o $br -p udp --dport=67:68 -j NFQUEUE --queue-bypass --queue-num $queue"`"
        sysevent set gre_${inst}_${br}_snoop_rule "$br_snoop_rule"

        br_snoop_rule_v6="`sysevent setunique v6GeneralPurposeFirewallRule " -A FORWARD -o $br -p udp --dport=546:547 -j NFQUEUE --queue-bypass --queue-num $queue"`"
        sysevent set gre_${inst}_${br}_snoop_rule_v6 "$br_snoop_rule_v6"

        br_mss_rule=`sysevent setunique GeneralPurposeMangleRule " -A POSTROUTING -o $br -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VAL"`
        sysevent set gre_${inst}_${br}_mss_rule "$br_mss_rule"
    done

    sysevent set gre_${inst}_current_bridges "$BRIDGES"

    
}
# TODO: verify indexes and proper teardown
#args gre ifname, "bridge list"
remove_bridge_config () {
        for br in $2; do
            if [ "$AB_SSID_DELIM" = $br ]; then
                continue
            fi
            sysevent set `sysevent get gre_${1}_${br}_snoop_rule`
            sysevent set `sysevent get gre_${1}_${br}_mss_rule`
            sysevent set `sysevent get gre_${1}_${br}_snoop_rule_v6`
        done
}

# NOTE: Hard coded solution
set_apisolation() {
    set '5 6'
    for i in $@; do
        dmcli eRT setv Device.WiFi.AccessPoint.$i.IsolationEnable bool true
    done
}

#args: hotspot instance
kill_procs () {
# TODO: develop scheme for only killing related pids. background task var $1 doesn't work as these processes daemonize
    killall $HOTSPOT_COMP
    sysevent set ${1}_keepalive_pid
	if [ -f /tmp/hotspot_arpd_up ]; then
		rm -rf /tmp/hotspot_arpd_up
	fi
    killall $GRE_ARP_PROC
    
}
#args: hotspot instance
hotspot_down() {

    inst=$1
    
    sysevent rm_async `sysevent get gre_wan_async`
    sysevent rm_async `sysevent get gre_ep_async`
    sysevent rm_async `sysevent get gre_primary_async`
    sysevent set gre_ep_async
    sysevent set gre_wan_async
    sysevent get gre_primary_async
    
    BRIDGE_INST_1=`psmcli get $HS_PSM_BASE.${inst}.interface.1.$GRE_PSM_BRIDGES`
    BRIDGE_INST_2=`psmcli get $HS_PSM_BASE.${inst}.interface.2.$GRE_PSM_BRIDGES`
    bridgeFQDM="$BRIDGE_INST_1 $BRIDGE_INST_2"
	
    remove_bridge_config ${inst} "`sysevent get gre_${inst}_current_bridges`"

    brinst=""
    OLD_IFS="$IFS"
    IFS=","
    IFS="$OLD_IFS"

    kill_procs $inst
    
    sysevent set `sysevent get ${inst}_arp_queue_rule`
    sysevent set ${inst}_arp_queue_rule
    
    sysevent set hotspotfd-tunnelEP
    sysevent set snooper-wifi-clients
    
    sysevent set hotspot_${inst}-status stopped
    
    sysevent set hotspot_ssids_up

}

update_vlan()
{
    TUNNELINST=$1
    OLDVLANID=$2

    LOWERBRIDGE=`psmcli get $HS_PSM_BASE.${TUNNELINST}.interface.1.$GRE_PSM_BRIDGES`
    BRIDGEINST=`echo $LOWERBRIDGE |cut -d . -f 4`
    BRIDGENAME=`dmcli eRT retv Device.Bridging.Bridge.${BRIDGEINST}.Name`

    #remove oldvlan
    if [ $OLDVLANID != "0" ]; then
        vconfig rem $GRE_IFNAME.${OLDVLANID}
    else
        brctl delif $BRIDGENAME $GRE_IFNAME
    fi

    #add new vlan
    VLANID=`psmcli get $HS_PSM_BASE.${TUNNELINST}.interface.1.VLANID`
    if [ $VLANID != "0" ]; then
        vconfig add $GRE_IFNAME $VLANID
        ifconfig $GRE_IFNAME.${VLANID} up
        brctl addif $BRIDGENAME $GRE_IFNAME.${VLANID}
    else
        brctl addif $BRIDGENAME $GRE_IFNAME
    fi
}

destroy_bridges_interfaces()
{
    TUNNELINST=$1

    LOWERBRIDGE=`psmcli get $HS_PSM_BASE.${TUNNELINST}.interface.1.$GRE_PSM_BRIDGES`
    BRIDGEINST=`echo $LOWERBRIDGE |cut -d . -f 4`

    BRIDGENAME=`dmcli eRT retv Device.Bridging.Bridge.${BRIDGEINST}.Name`
    ifconfig $BRIDGENAME down
    brctl delbr $BRIDGENAME
}

create_bridges_interfaces()
{
    TUNNELINST=$1

    LOWERBRIDGE=`psmcli get $HS_PSM_BASE.${TUNNELINST}.interface.1.$GRE_PSM_BRIDGES`
    BRIDGEINST=`echo $LOWERBRIDGE |cut -d . -f 4`

    BRIDGENAME=`dmcli eRT retv Device.Bridging.Bridge.${BRIDGEINST}.Name`
    BRIDGEEXITS=`ls /sys/devices/virtual/net/${BRIDGENAME}`

    #get wifi interface name
    WIFI24G=`dmcli eRT retv Device.WiFi.SSID.5.Name`
    WIFI5G=`dmcli eRT retv Device.WiFi.SSID.6.Name`

    #Create Bridge
    brctl addbr $BRIDGENAME
    ifconfig $BRIDGENAME up
    brctl addif $BRIDGENAME $WIFI24G
    brctl addif $BRIDGENAME $WIFI5G

    brctl show > /dev/console

    #create VLAN
    VLANID=`psmcli get $HS_PSM_BASE.${inst}.interface.1.VLANID`

    if [ $VLANID != "0" ]; then
        vconfig add $GRE_IFNAME $VLANID
        ifconfig $GRE_IFNAME.${VLANID} up
        brctl addif $BRIDGENAME $GRE_IFNAME.${VLANID}
    else
        brctl addif $BRIDGENAME $GRE_IFNAME
    fi

    nvram set lan2_ifname=$BRIDGENAME
    nvram set lan2_ifnames="$WIFI24G $WIFI5G"
    nvram commit
    rc restart

}
initialize_hotpsot()
{
        echo "GRE CREATE: $1"
        TUNNELINST=$1
        read_init_params $TUNNELINST

        #Initialize
        if [ x = x`sysevent get ${inst}_keepalive_pid` ]; then
            echo "GRE INITIALIZING..."
            async="`sysevent async hotspotfd-tunnelEP $THIS`"
            sysevent set gre_ep_async "$async" > /dev/null
            async="`sysevent async wan-status $THIS`"
            sysevent set gre_wan_async "$async" > /dev/null
            async="`sysevent async hotspotfd-primary $THIS`"
            sysevent set gre_primary_async "$async" > /dev/null

            init_keepalive_sysevents > /dev/null
            init_snooper_sysevents
            sysevent set snooper-log-enable 1
	    #create_bridges_interfaces $bridgeinst $TUNNELINST
            echo "Starting hotspot component"
            $HOTSPOT_COMP -subsys eRT. > /dev/null &
            sysevent set ${inst}_keepalive_pid $! > /dev/null
            sysevent set hotspot_${inst}-status started

            update_bridge_config $GRE_IFNAME > /dev/null
            arpFWrule=`sysevent setunique GeneralPurposeFirewallRule " -I OUTPUT -o $WAN_IF -p icmp --icmp-type 3 -j NFQUEUE --queue-bypass --queue-num $ARP_NFQUEUE"`
            sysevent set ${inst}_arp_queue_rule "$arpFWrule" > /dev/null
            $GRE_ARP_PROC -q $ARP_NFQUEUE  > /dev/null &
            echo "handle_gre : Triggering RDKB_FIREWALL_RESTART"
            sysevent set firewall-restart > /dev/null

        fi

        if [ x"up" = x`sysevent get if_${3}-status` ]; then
            echo ${TYPE}_READY=\"$3\"
        else
            echo ${TYPE}_READY=\"\"
        fi
}
#args: hotspot instance
hotspot_up() {
    inst=$1
    eval `psmcli get -e BRIDGE_INST_1 $HS_PSM_BASE.${inst}.interface.1.$GRE_PSM_BRIDGES BRIDGE_INST_2 $HS_PSM_BASE.${inst}.interface.2.$GRE_PSM_BRIDGES ENABLED $HS_PSM_BASE.${inst}.$HS_PSM_ENABLE GRE_ENABLED $GRE_PSM_BASE.${inst}.$GRE_PSM_ENABLE`

    if [ x"1" != x$ENABLED -o x"1" != x$GRE_ENABLED ]; then
        exit 0;
    fi


    set_apisolation $inst
    
    brinst=`echo $BRIDGE_INST_1 |cut -d . -f 4`
    initialize_hotpsot $inst
    
    sysevent set hotspot_${inst}-status started
    
}


#service_init
case "$1" in
#  Synchronous calls from bridge
    #Args: netid, members
      
#  Sysevent calls
    update-vlanID)
        ARGS=($2)     

        TUNNELINST=${ARGS[0]}
        OLDVLANID=${ARGS[1]}
        update_vlan $TUNNELINST $OLDVLANID
    ;;
    hotspotfd-tunnelEP)
        echo "GRE EP called : $2"
              inst=1

        if [ $2 = "recover" ] ; then                                    
             recover="true"                    
        fi        
 
        curep=`sysevent get gre_current_endpoint`                   
        if [ x != x$curep -a x$curep != x${2} ] || [ $recover = "true" ]; then
            destroy_tunnel $GRE_IFNAME
	    destroy_bridges_interfaces $inst 
        fi    


         if [ x"NULL" != x${2} ] || [ $recover = "true" ]; then
              if [ $recover = "true" ] ; then                                    
                  curep=`dmcli eRT retv Device.X_COMCAST-COM_GRE.Tunnel.1.PrimaryRemoteEndpoint`
                  echo "dmcli ip : $curep"                                   
                  create_tunnel $curep $GRE_IFNAME
              else
                  create_tunnel $2 $GRE_IFNAME
              fi

	      create_bridges_interfaces $inst

         fi           

    ;;
    
    wan-status)
    # Do not have a requirement to handle the case of wan-status change
    ;;
    
    snmp_subagent-status)
    # Do not have snmp in MNG
    ;;
    
    hotspot-start)
        if [ x"NULL" = x$2 ]; then
            allGreInst="`psmcli getallinst $HS_PSM_BASE.`"
            inst=`echo $allGreInst | cut -f 1`
            if [ x = x$inst ]; then
                exit 0
            fi
        else
            inst=$2
        fi
        hotspot_up $inst
    ;;
    
    hotspot-stop)
        if [ x"NULL" = x$2 ]; then
            allGreInst="`psmcli getallinst $HS_PSM_BASE.`"
            inst=`echo $allGreInst | cut -f 1`
            if [ x = x$inst ]; then
                exit 0
            fi
        else
            inst=$2
        fi

        destroy_tunnel $name
        destroy_bridges_interfaces $inst
        
        hotspot_down $inst
    ;;

    hotspot-restart)
        if [ "$2" = "NULL" ]; then
            inst=1
        else
            inst=$2
        fi
        TunnelEnable="`psmcli get $HS_PSM_BASE.$inst.$HS_PSM_ENABLE`"
        if [ -n "$TunnelEnable" ]; then
            if [ "$TunnelEnable" != "true" ]; then
               dmcli eRT setv Device.X_COMCAST-COM_GRE.Tunnel.$inst.Enable bool $TunnelEnable
            fi
        fi
    ;;
    
    #args: hotspot gre instance
    gre-restart|gre-forceRestart)
        curr_tunnel=`sysevent get gre_current_endpoint`
        # NOTE: assuming 1-to-1, identical gre to hotspot instance mapping
        hotspot_started=`sysevent get hotspot_${2}-status`
		
        eval `psmcli get -e BRIDGE_INST_1 $HS_PSM_BASE.${2}.interface.1.$GRE_PSM_BRIDGES BRIDGE_INST_2 $HS_PSM_BASE.${2}.interface.2.$GRE_PSM_BRIDGES ENABLED $HS_PSM_BASE.${2}.$HS_PSM_ENABLE GRE_ENABLED $GRE_PSM_BASE.${2}.$GRE_PSM_ENABLE name $GRE_PSM_BASE.$2.$GRE_PSM_NAME`

        bridgeFQDM="$BRIDGE_INST_1 $BRIDGE_INST_2"
		
        if [ x != x$curr_tunnel ]; then
            destroy_tunnel $name
            destroy_bridges_interfaces $2
        fi
        
        if [ x"1" != x$ENABLED -o x"1" != x$GRE_ENABLED ]; then
            #Disabled
            if [ xstarted = x$hotspot_started ]; then
                hotspot_down $2
            fi
        else
            #Enabled
            if [ xstarted = x$hotspot_started ]; then
                if [ x != x$curr_tunnel ]; then
                    create_tunnel $curr_tunnel $name
                    create_bridges_interfaces $2
                fi
            else
                initialize_hotpsot $2
            fi
        fi
    ;;
    
    #args: hotspot gre instance
    hotspot-update_bridges)
        eval `psmcli get -e BRIDGE_INST_1 $HS_PSM_BASE.${2}.interface.1.$GRE_PSM_BRIDGES BRIDGE_INST_2 $HS_PSM_BASE.${2}.interface.2.$GRE_PSM_BRIDGES NAME $GRE_PSM_BASE.$2.$GRE_PSM_NAME`
        BRIDGE_INSTS="$BRIDGE_INST_1 $BRIDGE_INST_2"
        start=""
        brinst=""
        OLD_IFS="$IFS"
        IFS="${AB_DELIM}${AB_SSID_DELIM}"
        for i in $BRIDGE_INSTS; do
            brinst=`echo $i |cut -d . -f 4`
            status=`sysevent get multinet_$brinst-status`
            if [ x = x$status -o x$STOPPED_STATUS = x$status ]; then
                sysevent set multinet-start $brinst
                start=1
            fi
        done
        IFS="$OLD_IFS"
        bInst_to_bNames "$BRIDGE_INSTS"
        update_bridge_config $NAME
        
        if [ x = x$start ]; then
          echo "handle_gre : Triggering RDKB_FIREWALL_RESTART in update bridges"
            sysevent set firewall-restart
        fi
    ;;
    
    #args: hotspot gre instance
    hotspot-update_tcpmss)
       allGreInst="`psmcli getallinst $HS_PSM_BASE.`"
       inst=`echo $allGreInst | cut -f 1`
       eval `psmcli get -e MSS_VAL $HS_PSM_BASE.${inst}.$GRE_PSM_TCPMSS`
       BRIDGE=`sysevent get gre_${inst}_current_bridges | cut -d ':' -f1 | cut -d ' ' -f1`
       if [ -z "$BRIDGE" ]
       then
               echo "handle_gre : Bridge instance not found. Exiting.."
               exit 0;
       fi

       sysevent set `sysevent get gre_${inst}_${BRIDGE}_mss_rule`

       if [ $MSS_VAL -ne 0 ]
       then
               br_mss_rule=`sysevent setunique GeneralPurposeMangleRule " -A POSTROUTING -o $BRIDGE -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VAL"`
               sysevent set gre_${inst}_${BRIDGE}_mss_rule "$br_mss_rule"
       fi

       echo "handle_gre : Triggering RDKB_FIREWALL_RESTART"
       sysevent set firewall-restart
    ;;
    *)
        exit 3
        ;;
esac
