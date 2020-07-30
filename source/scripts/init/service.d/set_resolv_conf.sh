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

RESOLV_CONF="/etc/resolv.conf"

#-----------------------------------------------------------------
# set the resolv.conf file
#-----------------------------------------------------------------

source /etc/utopia/service.d/service_dhcp_server/dhcp_server_functions.sh

prepare_resolv_conf () {
    SEARCH_DOMAIN=$(grep search $RESOLV_CONF)
    WAN_DNS_IPv4=$(sysevent get wan_dhcp_dns)
    WAN_DNS_IPv6=$(sysevent get ipv6_nameserver)

    echo -n > $RESOLV_CONF

    # Write domain.
    echo "$SEARCH_DOMAIN" >> $RESOLV_CONF

    # IPv4
    # Write loopback address in the beginning.
    echo "nameserver 127.0.0.1" >> $RESOLV_CONF

    # Write static configuration.
    get_static_dns_ips ipv4 wan
    for ip in $STATIC_DNS_IPv4
    do
        echo "nameserver $ip" >> $RESOLV_CONF
    done

    # Write DHCP configuration.
    if [ -z "$STATIC_DNS_IPv4" ] ; then
        for ip in $WAN_DNS_IPv4;
        do
            echo "nameserver $ip" >> $RESOLV_CONF
        done
    fi

    # IPv6
    # Write loopback address in the beginning.
    echo "nameserver ::1" >> $RESOLV_CONF

    # Write static configuration.
    get_static_dns_ips ipv6 wan
    for ip in $STATIC_DNS_IPv6
    do
        echo "nameserver $ip" >> $RESOLV_CONF
    done

    # Write DHCP configuration.
    if [ -z "$STATIC_DNS_IPv6" ] ; then
        for ip in $WAN_DNS_IPv6;
        do
            echo "nameserver $ip" >> $RESOLV_CONF
        done
    fi

    if [ "$(syscfg get wan_proto)" = "static" ] ; then
        WAN_STATIC_DOMAIN=$(syscfg get wan_domain)
        if [ -n "$WAN_STATIC_DOMAIN" ] ; then
            echo "search $WAN_STATIC_DOMAIN" >> $RESOLV_CONF
        fi
    fi

    # Restart DHCP server.
    sysevent set dhcp_server-restart
}

prepare_resolv_conf

