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

ls /tmp/pam_initialized* > /tmp/pam_init_status

source /etc/utopia/service.d/log_capture_path.sh
source /etc/utopia/service.d/utctx_helper.sh
source /etc/device.properties

dmesg -n 5

echo_t "*******************************************************************"
echo_t "*                                                                  "
echo_t "[utopia][init] P-UNIT status"
cat /proc/P-UNIT/status
echo_t "*                                                                  "
echo_t "*******************************************************************"

if [ "$BOX_TYPE" = "XB3" ];then
    RESERVED_PORTS="58081,50755,50757,50759,50760"
    sysctl -w net.ipv4.ip_local_reserved_ports="$RESERVED_PORTS"

fi

# Do not accept ICMP redirects and source routed packets (prevent MITM attacks)

if [ "$BOX_TYPE" = "XB3" ];then
    conf_file="/etc/traffic-filter.conf"
    if [ -e $conf_file ] 
    then
        echo_t "Setup sysctl config from file \"$conf_file\" "
        sysctl -p $conf_file
    fi
fi

echo_t "Starting log module.."
/usr/sbin/log_start.sh

cat /etc/dhcp_static_hosts > /var/tmp/dhcp_static_hosts
cat /etc/hosts > /var/tmp/hosts

mount --bind /var/tmp/dhcp_static_hosts /etc/dhcp_static_hosts
mount --bind /var/tmp/hosts /etc/hosts

BUTTON_THRESHOLD=15

FACTORY_RESET_REASON="false"
PUNIT_RESET_DURATION=0

changeFilePermissions() {
       if [ -e "$1" ]; then
               filepermission=$(stat -c %a "$1")
               if [ "$filepermission" -ne "$2" ]
               then
                       chmod "$2" "$1"
                       echo "[utopia][init] Modified File Permission to $2 for file - $1"
               fi
       else
               echo "[utopia][init] changeFilePermissions: file $1 doesn't exist"
       fi
}

CheckAndReCreateDB()
{
	NVRAMFullStatus=`df -h /nvram | grep "100%"`
	if [ -n "$NVRAMFullStatus" ]; then
		if [ -f "/rdklogger/rdkbLogMonitor.sh" ]
		then
			  #Remove Old backup files if there	
			  sh /rdklogger/rdkbLogMonitor.sh "remove_old_logbackup"		 

		  	  #Re-create syscfg create again
			  syscfg_create -f /tmp/syscfg.db
			  if [ $? != 0 ]; then
				  NVRAMFullStatus=`df -h /nvram | grep "100%"`
				  if [ -n "$NVRAMFullStatus" ]; then
					 echo_t "[utopia][init] NVRAM Full(100%) and below is the dump"
					 du -h /nvram 
					 ls -al /nvram	 
				  fi
			  fi 
		fi
	fi 
}

if [ -f /usr/rdk/migration-mng/migration-mng ]; then
	echo_t "[utopia][init] Starting migration manager"
	/usr/rdk/migration-mng/migration-mng
fi

echo_t "[utopia][init] Starting syscfg using file store (/nvram/syscfg.db)"

# remove syscfg tmp files from nvram during bootup
rm -f /nvram/syscfg_tmp.db_*

if [ -f /nvram/syscfg.db ]; then

   if [ -f /nvram/bootconfig_custindex ]; then

      if [ -x /usr/bin/db_mig ]; then
         # Preserve value of db_migration_complete before resetting /nvram/syscfg.db
         DB_MIG_COMPLETE=$(grep "db_migration_complete" /nvram/syscfg.db | cut -d "=" -f2)
      fi

      # If Customer index is set via boot config then ignore /nvram/syscfg.db
      echo -n > /tmp/syscfg.db
   else
      cp /nvram/syscfg.db /tmp/syscfg.db
   fi

   syscfg_create -f /tmp/syscfg.db
   if [ $? != 0 ]; then
	   CheckAndReCreateDB
   fi

   if [ -f /nvram/bootconfig_custindex ]; then
      # Setting preserved value of db_migration_completed
      if [ -x /usr/bin/db_mig ] && [ "$DB_MIG_COMPLETE" = "true" ]; then
         echo_t "[utopia][init] dbmig = $DB_MIG_COMPLETE"
         syscfg set db_migration_completed $DB_MIG_COMPLETE
      fi
      # Ensure that syscfg has been written back to Flash before
      # CUSTOMER_BOOT_CONFIG_FILE is removed (see below) to avoid race if
      # power is lost after removing CUSTOMER_BOOT_CONFIG_FILE but before
      # syscfg data containing the new customer ID has been saved to Flash.
      syscfg commit
   fi

else
   echo -n > /tmp/syscfg.db
   echo -n > /nvram/syscfg.db
   syscfg_create -f /tmp/syscfg.db
   if [ $? != 0 ]; then
        CheckAndReCreateDB
   fi
   #>>zqiu
   echo_t "[utopia][init] need to reset wifi when /nvram/syscfg.db file is not available"
   syscfg set factory_reset w
   syscfg commit
   #<<zqiu
   touch /nvram/.apply_partner_defaults
   # Put value 204 into networkresponse.txt file so that
   # all LAN services start with a configuration which will
   # redirect everything to Gateway IP.
   # This value again will be modified from network_response.sh 
   echo_t "[utopia][init] Echoing network response during Factory reset"
   echo 204 > /var/tmp/networkresponse.txt
fi

# Get the values of FactoryResetSSID's from the psm xml backup file
WIFI_FACTORY_RESET_SSID1=$(grep -ir '1.FactoryResetSSID' /nvram/bbhm_bak_cfg.xml | awk -F"[<>]" '{print $3}')
WIFI_FACTORY_RESET_SSID2=$(grep -ir '2.FactoryResetSSID' /nvram/bbhm_bak_cfg.xml | awk -F"[<>]" '{print $3}')

if [ -x /usr/bin/db_mig ]; then
   DB_MIG_COMPLETE=$(syscfg get db_migration_completed)
   echo_t "[utopia][init] db_mig = $DB_MIG_COMPLETE"
fi

# Read reset duration to check if the unit was rebooted by pressing the HW reset button
if cat /proc/P-UNIT/status | grep -q "Reset duration from shadow register"; then
   # Note: Only new P-UNIT firmwares and Linux drivers (>= 1.1.x) support this.
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Reset duration from shadow register"|awk -F '[ |\.]' '{ print $9 }'`
   # Clear the Reset duration from shadow register value
   # echo "1" > /proc/P-UNIT/clr_reset_duration_shadow
   touch /var/tmp/utopia_cleared_shadow_reg.txt
   clean_reset_duration;
elif cat /proc/P-UNIT/status | grep -q "Last reset duration"; then
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Last reset duration"|awk -F '[ |\.]' '{ print $7 }'`
else
   echo_t "[utopia][init] Cannot read the reset duration value from /proc/P-UNIT/status"
fi

# Set the factory reset key if it was pressed for longer than our threshold
if [ "$PUNIT_RESET_DURATION" -gt "$BUTTON_THRESHOLD" ]
then
   syscfg set factory_reset y
   syscfg commit
   BUTTON_FR="1"
   SYSCFG_FR_VAL="y"
else
   SYSCFG_FR_VAL="$(syscfg get factory_reset)"
fi

SYSCFG_LastRebootReason="$(syscfg get X_RDKCENTRAL-COM_LastRebootReason)"

if [ "$SYSCFG_FR_VAL" = "y" ]
then
   echo_t "[utopia][init] Performing factory reset"

   # Remove log file first because it need get log file path from syscfg   
   /usr/sbin/log_handle.sh reset
   syscfg_destroy -f

   # Remove syscfg and PSM storage files
   #mark the factory reset flag 'on'
   FACTORY_RESET_REASON="true" 
   rm -f /nvram/partners_defaults.json 
   rm -f /nvram/bootstrap.json
   rm -f /opt/secure/RFC/tr181store.json
   rm -f /opt/secure/Blocklist_file.txt
   rm -f /nvram/Blocklist_XB3.txt
   rm -f /nvram/syscfg.db
   rm -f /tmp/syscfg.db
   rm -f /nvram/bbhm_bak_cfg.xml
   rm -f /nvram/bbhm_tmp_cfg.xml
   rm -f /nvram/TLVData.bin
   rm -f /nvram/reverted
   rm -f /nvram/dnsmasq_servers.conf
   rm -f /nvram/.FirmwareUpgradeStartTime
   rm -f /nvram/.FirmwareUpgradeEndTime
   # Remove DHCP lease file
   rm -f /nvram/dnsmasq.leases
   rm -f /nvram/server-IfaceMgr.xml
   rm -f /nvram/server-AddrMgr.xml
   rm -f /nvram/server-CfgMgr.xml
   rm -f /nvram/server-TransMgr.xml
   rm -f /nvram/server-cache.xml
   rm -f /nvram/server-duid
   rm -f /nvram/.keys/*
   if [ -f /etc/ONBOARD_LOGGING_ENABLE ]; then
    # Remove onboard files
    rm -f /nvram/.device_onboarded
    rm -f /nvram/DISABLE_ONBOARD_LOGGING
    rm -rf /nvram2/onboardlogs
   fi
   if [ -f /etc/WEBCONFIG_ENABLE ]; then
   # Remove webconfig_db.bin on factory reset on all RDKB platforms
     rm -f /nvram/webconfig_db.bin     
   fi

   rm -f /nvram/hotspot_blob
   rm -f /nvram/hotspot.json

    if [ -f "/nvram/dnsmasq.vendorclass" ];then
      rm -f /nvram/dnsmasq.vendorclass
    fi

     touch /nvram/.apply_partner_defaults   
   #>>zqiu
   create_wifi_default
   #<<zqiu
   echo_t "[utopia][init] Retarting syscfg using file store (/nvram/syscfg.db)"
   touch /tmp/syscfg.db
   touch /nvram/syscfg.db
   syscfg_create -f /tmp/syscfg.db
   if [ $? != 0 ]; then
	   CheckAndReCreateDB
   fi
   
#>>zqiu
   # Put value 204 into networkresponse.txt file so that
   # all LAN services start with a configuration which will
   # redirect everything to Gateway IP.
   # This value again will be modified from network_response.sh 
   echo_t "[utopia][init] Echoing network response during Factory reset"
   echo 204 > /var/tmp/networkresponse.txt

   # If db_migration_completed was true before then make that persistent across factory resets.
   if [ -x /usr/bin/db_mig ] && [ "$DB_MIG_COMPLETE" = "true" ]; then
      echo_t "[utopia][init] dbmig during Factory reset = $DB_MIG_COMPLETE"
      syscfg set db_migration_completed $DB_MIG_COMPLETE
      syscfg commit
   fi

elif [ "$SYSCFG_FR_VAL" = "w" ]; then
    echo_t "[utopia][init] Performing WiFi reset"
    create_wifi_default
    syscfg unset factory_reset
fi

# Set the wifi_factory_reset_ssid accordingly to the value fetched from the PSM backup file
if [ "$WIFI_FACTORY_RESET_SSID1" = "1" ] || [ "$WIFI_FACTORY_RESET_SSID2" = "1" ]; then
    syscfg set wifi_factory_reset_ssid 1
    syscfg commit
else
    syscfg set wifi_factory_reset_ssid 0
    syscfg commit
fi

#echo_t "[utopia][init] Cleaning up vendor nvram"
# /etc/utopia/service.d/nvram_cleanup.sh

# In case customer index and factory reset happens at the same time,
# syscfg_create is called for two times. So remove bootconfig_custindex file after that.
if [ -f /nvram/bootconfig_custindex ]; then
    # Remove /nvram/bootconfig_custindex file. Customer specific values are already added in syscfg.
    rm -f /nvram/bootconfig_custindex
fi

#CISCOXB3-6085:Removing current configuration from nvram as a part of PSM migration.
if [ -f /nvram/bbhm_cur_cfg.xml  ]; then
       mv /nvram/bbhm_cur_cfg.xml /tmp/bbhm_cur_cfg.xml
elif [ -f /nvram/bbhm_bak_cfg.xml  ]; then	
	cp -f /nvram/bbhm_bak_cfg.xml /tmp/bbhm_cur_cfg.xml
fi

if [ -f /usr/ccsp/psm/lg_bbhm_patch.sh ]
then
    /usr/ccsp/psm/lg_bbhm_patch.sh /tmp/bbhm_cur_cfg.xml
fi

#echo_t "[utopia][init] Starting system logging"
#/etc/utopia/service.d/service_syslog.sh syslog-start

# update max number of msg in queue based on system maximum queue memory.
# This update will be used for presence detection feature.
MSG_SIZE_MAX=`cat /proc/sys/fs/mqueue/msgsize_max`
MSG_MAX_SYS=`ulimit -q`
TOT_MSG_MAX=50
if [ -z "$MSG_MAX_SYS" ]; then
echo "ulimit cmd not avail assign mq msg_max :$TOT_MSG_MAX"
else
TOT_MSG_MAX=$((MSG_MAX_SYS/MSG_SIZE_MAX))
echo "mq msg_max :$TOT_MSG_MAX"
fi

echo $TOT_MSG_MAX > /proc/sys/fs/mqueue/msg_max

echo_t "[utopia][init] Starting sysevent subsystem"
#syseventd --threads 18
syseventd

sleep 1 
echo_t "[utopia][init] Setting any unset system values to default"
apply_system_defaults
changeFilePermissions /nvram/syscfg.db 400

echo "[utopia][init] SEC: Syscfg stored in /nvram/syscfg.db"

queries="lan_ipaddr lan_netmask ForwardSSH unit_activated lan_ifname cmdiag_ifname ecm_wan_ifname nat_udp_timeout nat_tcp_timeout nat_icmp_timeout lan_ethernet_physical_ifnames"
get_utctx_val "$queries"

# Log to check the DHCP range corruption after system defaults applied
echo_t "[utopia][init] lan_ipaddr = $SYSCFG_lan_ipaddr lan_netmask = $SYSCFG_lan_netmask"

if [ "$SYSCFG_ForwardSSH" = "true" ]
then
    echo "SSH: Forward SSH changed to enabled" >> /rdklogs/logs/FirewallDebug.txt
else
    echo "SSH: Forward SSH changed to disabled" >> /rdklogs/logs/FirewallDebug.txt
fi

# syscfg "unit_activated" is set from network_response.sh based on the return code received.
echo_t "[utopia][init] Value of unit_activated got is: $SYSCFG_unit_activated"
if [ "$SYSCFG_unit_activated" = "1" ]
then
    echo_t "[utopia][init] Echoing network response during Reboot"
    echo 204 > /var/tmp/networkresponse.txt
fi 

echo_t "[utopia][init] Applying iptables settings"

#disable telnet / ssh ports
iptables -A INPUT -i "$SYSCFG_lan_ifname" -p tcp --dport 23 -j DROP
iptables -A INPUT -i "$SYSCFG_lan_ifname" -p tcp --dport 22 -j DROP
iptables -A INPUT -i "$SYSCFG_cmdiag_ifname" -p tcp --dport 23 -j DROP
iptables -A INPUT -i "$SYSCFG_cmdiag_ifname" -p tcp --dport 22 -j DROP

ip6tables -A INPUT -i "$SYSCFG_lan_ifname" -p tcp --dport 23 -j DROP
ip6tables -A INPUT -i "$SYSCFG_lan_ifname" -p tcp --dport 22 -j DROP
ip6tables -A INPUT -i "$SYSCFG_cmdiag_ifname" -p tcp --dport 23 -j DROP
ip6tables -A INPUT -i "$SYSCFG_cmdiag_ifname" -p tcp --dport 22 -j DROP

#protect from IPv6 NS flooding
ip6tables -t mangle -A PREROUTING -i "$SYSCFG_ecm_wan_ifname" -d ff00::/8 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j DROP
ip6tables -t mangle -A PREROUTING -i "$SYSCFG_wan_ifname" -d ff00::/8 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j DROP

echo 60 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout
echo 120 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream
echo 240 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent
echo 240 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
echo 60 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close
echo 20 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
echo 400 > /proc/sys/net/netfilter/nf_conntrack_expect_max

if [ "$BOX_TYPE" = "MV1" ]; then
    echo 8192  > /proc/sys/net/netfilter/nf_conntrack_max
else
    echo 16384 > /proc/sys/net/netfilter/nf_conntrack_max
fi

echo $SYSCFG_nat_udp_timeout > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
echo $SYSCFG_nat_tcp_timeout > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
echo $SYSCFG_nat_icmp_timeout > /proc/sys/net/netfilter/nf_conntrack_icmp_timeout

#/sbin/ulogd -c /etc/ulogd.conf -d

echo_t "[utopia][init] Processing registration"
# run all executables in the sysevent registration directory
# echo_t "[utopia][init] Running registration using /etc/utopia/registration.d"
execute_dir /etc/utopia/registration.d &
#init_inter_subsystem&

export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/run/dbus/system_bus_socket

if [ "$BOX_TYPE" = "XB3" ];then
	/usr/bin/dbus-daemon --config-file=/usr/ccsp/basic.conf --fork
fi

#start  ntpd server on ARM
NTP_CONF=/etc/ntp.conf
NTP_CONF_TMP=/tmp/ntp.conf
if [ "$BOX_TYPE" = "XB3" ]
then
	cp $NTP_CONF $NTP_CONF_TMP
	echo "interface ignore wildcard" >> $NTP_CONF_TMP
	echo "interface listen $ARM_INTERFACE_IP" >> $NTP_CONF_TMP
	ntpd -c $NTP_CONF_TMP 
fi

# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

# Temp disable radius vlan for Mv1

if [ "$BOX_TYPE" != "MV1" ]
then

# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

#--------Set up Radius vlan -------------------
vconfig add l2sd0 4090
if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "MV1" ];then
	/etc/utopia/service.d/service_multinet_exec add_radius_vlan &
else
	/etc/utopia/service.d/service_multinet/handle_sw.sh addVlan 0 4090 sw_6 
fi
ifconfig l2sd0.4090 192.168.251.1 netmask 255.255.255.0 up
ip rule add from all iif l2sd0.4090 lookup erouter


# RDKB-15951 : Dedicated l2sd0 vlan for Mesh Bhaul
vconfig add l2sd0 1060
if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "MV1" ];then
        /etc/utopia/service.d/service_multinet_exec add_meshbhaul_vlan &
else
        /etc/utopia/service.d/service_multinet/handle_sw.sh addVlan 0 1060 sw_6
fi
ifconfig l2sd0.1060 up
ip rule add from all iif l2sd0.1060 lookup erouter

# Add QinQ for pod ethernet backhaul traffic
brctl addbr br403
ifconfig br403 192.168.245.1 netmask 255.255.255.0 up
brctl addif br403 l2sd0.1060
ip rule add from all iif br403 lookup erouter

# Add a new bridge for ethernet bhaul delivery
brctl addbr brebhaul
ifconfig brebhaul 169.254.85.1 netmask 255.255.255.0 up

#--------Marvell LAN-side egress flood mitigation----------------
echo_t "88E6172: Do not egress flood unicast with unknown DA"
swctl -c 11 -p 5 -r 4 -b 0x007b

# Creating IOT VLAN on ARM
if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "MV1" ];then
    /etc/utopia/service.d/service_multinet_exec add_IOT_vlan &
else
    /etc/utopia/service.d/service_multinet/handle_sw.sh addVlan 0 4090 sw_6
fi

# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

# Temp disable radius vlan for Mv1

fi

#--------MV1 Mesh Bhaul ----------------------------------------------

if [ "$BOX_TYPE" = "MV1" ];then
    /etc/utopia/service.d/service_multinet_exec create_mesh_vlan &
fi

# ------ Creating trunk port for ext switch ports of primary LAN --------------------
if [ "$BOX_TYPE" = "MV1" ]; then
    for l2switchPort in $SYSCFG_lan_ethernet_physical_ifnames
    do
        vconfig add ${l2switchPort%%.*} ${l2switchPort##*.}
        ip link set dev ${l2switchPort} up
    done
fi

# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

# Check and set factory-reset as reboot reason 
if [ "$FACTORY_RESET_REASON" = "true" ]; then
   if [ -f /nvram/.image_upgrade_and_FR_done ] && [ "$BOX_TYPE" = "VNTXER5" ]; then
       echo "[utopia][init] Detected last reboot reason as FirmwareDownloadAndFactoryReset"
       if [ -e "/usr/bin/onboarding_log" ]; then
           /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as FirmwareDownloadAndFactoryReset"
       fi
       syscfg set X_RDKCENTRAL-COM_LastRebootReason "FirmwareDownloadAndFactoryReset"
       syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
       rm -f /nvram/.image_upgrade_and_FR_done
   else
       echo_t "[utopia][init] Detected last reboot reason as factory-reset"
       if [ -e "/usr/bin/onboarding_log" ]; then
          /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as factory-reset"
       fi
       syscfg set X_RDKCENTRAL-COM_LastRebootReason "$SYSCFG_LastRebootReason"
       syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
   fi
else
   rebootReason="$SYSCFG_LastRebootReason"
   rebootCounter=`syscfg get X_RDKCENTRAL-COM_LastRebootCounter`
   echo_t "[utopia][init] X_RDKCENTRAL-COM_LastRebootReason ($rebootReason)"
   if [ "$rebootReason" = "factory-reset" ]; then
      echo_t "[utopia][init] Setting last reboot reason as unknown"
      syscfg set X_RDKCENTRAL-COM_LastRebootReason "unknown"
   fi

   # Check and set last reboot reason for Power-On Reset ( Broadcom specific )
   if [ -f /proc/device-tree/bolt/reset-list ]; then
      case $(cat /proc/device-tree/bolt/reset-list) in
         "power_on"|"main_chip_input,power_on"|"power_on,main_chip_input")
            syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
            syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
            ;;
      esac
   fi

      if [ "`cat /proc/P-UNIT/status|grep "Last reset origin"|awk '{ print $9 }'`" == "RESET_ORIGIN_HW" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	 if [ -e "/usr/bin/onboarding_log" ]; then
	     /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as HW or Power-On Reset"
	 fi
#ifdef CISCO_XB3_PLATFORM_CHANGES
         ##Work around: RDKB3939-500: /nvram/RDKB3939-500_RebootNotByPwrOff file not created by utopia.service(atom side) in case of power off shut down
      elif ( [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3939B" ] ) && [ "`cat /proc/P-UNIT/status|grep "Last reset origin"|awk '{ print $9 }'`" == "RESET_ORIGIN_ATOM" ] && [ ! -f "/nvram/RDKB3939-500_RebootNotByPwrOff" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	 if [ -e "/usr/bin/onboarding_log" ]; then
	     /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as HW or Power-On Reset"
	 fi
##LastRebootReason is set as BBU-Reset if the file /nvram/reboot.txt is present
      elif [ -f "/nvram/reboot.txt" ]; then
      	if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "BBU-Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/reboot.txt
      	fi
	  #Last reboot reason set as "PCD-reboot"  if the file /nvram/pcd_reboot_reason.txt is present
      elif [ -f "/nvram/pcd_reboot_reason.txt" ]; then
#        if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         echo_t "[utopia][init] Setting last reboot reason as PCD-reboot"
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "PCD-reboot"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/pcd_reboot_reason.txt
#        fi
#endif
##LastRebootReason is set as DOCSIS_SNMP_REBOOT if the file /nvram/CISCO_DOCSIS_SNMP_REBOOT is present
      elif [ -f "/nvram/CISCO_DOCSIS_SNMP_REBOOT" ]; then
      	if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "DOCSIS_SNMP_REBOOT"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/CISCO_DOCSIS_SNMP_REBOOT
      	fi
      else
         RESET_DURATION=`cat /proc/P-UNIT/status|grep "Last reset duration"|awk '{ print $7 }'`
         result=`echo "$RESET_DURATION $BUTTON_THRESHOLD"| awk '{if ($1 > 0 && $1 < $2) print $1}'`
         if [ -n "$result" ]; then
            syscfg set X_RDKCENTRAL-COM_LastRebootReason "pin-reset"
            syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	    if [ -e "/usr/bin/onboarding_log" ]; then
	        /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as pin-reset"
	    fi
         fi

#ifdef CISCO_XB3_PLATFORM_CHANGES
      	  if [ -e "/proc/P-UNIT/status" ]; then
	         Punit_status=`grep -i "Last reset origin" /proc/P-UNIT/status | awk '{print $9}'`
	         if [ "$Punit_status" = "RESET_ORIGIN_DOCSIS_WATCHDOG" ] && [ "$rebootReason" = "Software_upgrade" ] && [ "$rebootCounter" = "1" ] && [ -e "/nvram/reboot_due_to_sw_upgrade" ];then
                     echo_t "[utopia][init] Setting last reboot reason as Software_upgrade_Watchdog_Reboot"
                     syscfg set X_RDKCENTRAL-COM_LastRebootReason "Software_upgrade_Watchdog_Reboot"
                     syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	         elif ( [ "$rebootCounter" = "0" ] ) && ( [ "$Punit_status" = "RESET_ORIGIN_ATOM_WATCHDOG" ] || [ "$Punit_status" = "RESET_ORIGIN_DOCSIS_WATCHDOG" ] || [ "$Punit_status" = "RESET_ORIGIN_ATOM" ] );then
	             syscfg set X_RDKCENTRAL-COM_LastRebootReason "$Punit_status"
	             syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
		     if [ -e "/usr/bin/onboarding_log" ]; then
		         /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as $Punit_status"
		     fi
		fi
	         if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "MV1" ];then
	             Punit_Reset_Reason=`grep -i "Last reset reason" /proc/P-UNIT/status | awk '{print $9}'`
	             if [ "$Punit_Reset_Reason" = "RESET_WARM" ] && [ "$Punit_status" = "RESET_ORIGIN_DOCSIS" ];then
	                   syscfg set X_RDKCENTRAL-COM_LastRebootReason "HOST-OOPS-REBOOT"
	                   syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	             fi
	         fi
         fi
#endif
      fi
fi

if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ] || [ "$BOX_TYPE" = "MV1" ]; then
    if [ -f /nvram/restore_reboot ];then
	syscfg set X_RDKCENTRAL-COM_LastRebootReason "restore-reboot"
	syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"

        if [ -f /nvram/bbhm_cur_cfg.xml-temp ]; then
            ##Work around: TCCBR-4087 Restored saved configuration is not restoring wan Static IP.
            ##after untar the new bbhm current config is overrriden/corrupted at times.
            ##Hence we are storing a backup and replacing it to current config upon such cases
            a=`md5sum /nvram/bbhm_cur_cfg.xml-temp`
            a=$(echo "$a" | cut -f 1 -d " ")
            b=`md5sum /tmp/bbhm_cur_cfg.xml`
            b=$(echo "$b" | cut -f 1 -d " ")
            if [[ $a != "$b" ]]; then
               cp /nvram/bbhm_cur_cfg.xml-temp /tmp/bbhm_cur_cfg.xml
            fi
            rm -f /nvram/bbhm_cur_cfg.xml-temp
        fi
    fi
    rm -f /nvram/restore_reboot
    rm -f /nvram/bbhm_bak_cfg.xml.prev
    rm -f /nvram/syscfg.db.prev
fi

syscfg commit

#Printing the last reboot reason on device console
echo " Last Reboot Reason is $rebootReason" >> /dev/console

if [ "$BOX_TYPE" = "MV3" ]
then
	/usr/bin/logger -p local0.crit -t NETWORK "$(date +'%a %b %d %T %Y') CPE Reboot because of - $rebootReason"
fi

#ifdef CISCO_XB3_PLATFORM_CHANGES
## Remove after setting last reboot reason
if [ -f "/nvram/RDKB3939-500_RebootNotByPwrOff" ]; then
	rm /nvram/RDKB3939-500_RebootNotByPwrOff
fi
#endif 

if [ -f /usr/bin/rpcserver ]; then
    echo_t "[utopia][init] Starting rpcserver in arm"
    nice -n -10 /usr/bin/rpcserver &
fi

# Remove webconfig_db.bin on factory reset on XB3 platforms,CISCOXB3-6731
if [ "$FACTORY_RESET_REASON" = "true" ] && [ "$BOX_TYPE" = "XB3" ];then
    rpcclient2 "rm -f /nvram/webconfig_db.bin"
    rpcclient2 "rm -f /nvram/Blocklist_XB3.txt"
fi

#set ntp status as unsynchronized on bootup
syscfg set ntp_status 2

echo_t "[utopia][init] setting Multicast MAC before any switch configs"
/etc/utopia/service.d/service_multinet_exec set_multicast_mac &

if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
	echo_t "[utopia][init] started dropbear process"
	/etc/utopia/service.d/service_sshd.sh sshd-start &
fi

# Create a psm default file which contains customer-specific values
/usr/bin/psm_defaults_create

# If Customer index changed then remove psm db from nvram
SYSCFG_CUST_CHANGED="$(syscfg get customer-index-changed)"
if [ "${SYSCFG_CUST_CHANGED}" = "true" ]; then
    rm -f /tmp/bbhm_cur_cfg.xml /nvram/bbhm_bak_cfg.xml
    syscfg unset customer-index-changed
    syscfg commit
fi

if [ -x /usr/bin/db_mig ] && [ "$DB_MIG_COMPLETE" != "true" ]; then
    echo_t "[utopia][init] Running db_mig utility"
    /usr/bin/db_mig
    syscfg set db_migration_completed true
    syscfg commit
fi

if [ "$BOX_TYPE" = "MV1" ]; then
    if [ -f /nvram/O/eventcode.dat ] && grep -qF "0 BOOTSTRAP" /nvram/O/eventcode.dat; then
        echo_t "[utopia][init] 0 BOOTSTRAP is already set"
    else
        echo "0 BOOTSTRAP||" >> /nvram/O/eventcode.dat
    fi
fi
