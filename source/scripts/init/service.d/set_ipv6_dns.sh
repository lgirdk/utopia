#!/bin/sh
#######################################################################
# Copyright 2018-2019 ARRIS Enterprises, LLC.
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
#######################################################################
source /etc/utopia/service.d/service_dhcp_server/dhcp_server_functions.sh

#dibbler_conf=/etc/dibbler/server.conf
#/etc/dibbler/server.conf is soft link of /var/tmp/dhcp6s.conf
#sed operation on soft link will delete the soft link.
#Hence process on the actual configuration file.
dibbler_conf=/var/tmp/dhcp6s.conf
zebra_conf=/var/zebra.conf
tool=$1
ips=""
dns_proxy=`syscfg get dns_relay_enable`
dhcp_dns_ips=`sysevent get ipv6_nameserver`
DNS_OVERRIDE=`syscfg get dns_override`

if [ "$DNS_OVERRIDE" == "true" ] ; then
    DNS_IPv6_PREFERRED=`syscfg get dns_ipv6_preferred`
    DNS_IPv6_ALTERNATE=`syscfg get dns_ipv6_alternate`
    if [ -n "$DNS_IPv6_PREFERRED" ] ; then
        ips=$DNS_IPv6_PREFERRED
    fi
    if [ -n "$DNS_IPv6_ALTERNATE" ] ; then
        ips=$ips" "$DNS_IPv6_ALTERNATE
    fi
else
    if [ "$dns_proxy" == "1" ] ; then
        ips=`sysevent get lan_ipaddr_v6`
    else
        # Get LAN static configuration.
        get_static_dns_ips ipv6 lan
        if [ -z "$STATIC_DNS_IPv6" ] ; then
            # Get WAN static configuration.
            get_static_dns_ips ipv6 wan
        fi

        if [ -z "$STATIC_DNS_IPv6" ] ; then
            # Use dynamic configuration.
            ips=$dhcp_dns_ips
        else
            # Use static configuration.
            ips=$STATIC_DNS_IPv6
        fi
    fi
fi

# Trim spaces.
shopt -s extglob
ips="${ips%%*( )}"
shopt -u extglob

if [ "$tool" == "dibbler" ] ; then
    ips="${ips// /,}"
    sed -ri "s/ *dns-server.*$/ dns-server $ips/g" $dibbler_conf
elif [ "$tool" == "zebra" ] ; then
    ops=""
    for ip in $ips;
    do
        if [ -z "$ops" ] ; then
            ops="   ipv6 nd rdnss $ip 300"
        else
            ops="$ops\n   ipv6 nd rdnss $ip 300"
        fi
    done

    sed -ri "/ipv6 nd rdnss.*$/d" $zebra_conf
    IFS=
    while read -r line
    do
        echo "$line"
        if [[ "$line" == *"router-preference"* ]] ; then
            echo -e "$ops"
        fi
    done < $zebra_conf > $zebra_conf".tmp" && mv $zebra_conf".tmp" $zebra_conf
fi
