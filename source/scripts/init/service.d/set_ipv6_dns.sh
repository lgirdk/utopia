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

#dibbler_conf=/etc/dibbler/server.conf
#/etc/dibbler/server.conf is soft link of /var/tmp/dhcp6s.conf
#sed operation on soft link will delete the soft link.
#Hence process on the actual configuration file.
dibbler_conf=/var/tmp/dhcp6s.conf
zebra_conf=/var/zebra.conf
tool=$1
ips=""
STATIC_DNS_IPv6=""

eval `utctx_cmd get dns_relay_enable dns_override dns_static_server_count dns_ipv6_preferred dns_ipv6_alternate`
dns_proxy=$SYSCFG_dns_relay_enable
dhcp_dns_ips=`sysevent get ipv6_nameserver`
DNS_OVERRIDE=$SYSCFG_dns_override

get_static_dns_ips () {
    ind=1
    static_ips=""
    interface="unknown"
    delim=":"

    if [ "$1" == "wan" ] ; then
        interface="Device.IP.Interface.1"
    elif [ "$1" == "lan" ] ; then
        interface="Device.IP.Interface.3"
    fi

    count=$SYSCFG_dns_static_server_count
    if [ -z "$count" ] ; then
        count="0"
    fi
    while [ "$ind" -le "$count" ]
    do
        ns=`syscfg get dns_static_server_$ind`
        enabled=`syscfg get $ns enable`
        if=`syscfg get $ns if`
        if [ "$enabled" == "1" ] && [ "$if" == "$interface" ] ; then
            ip=`syscfg get $ns ip | grep $delim`
            if [ -n "$ip" ] ; then
                static_ips=$static_ips""$ip" "
            fi
        fi
        ((ind++))
    done

    STATIC_DNS_IPv6=$static_ips
}

if [ "$DNS_OVERRIDE" == "true" ] ; then
    DNS_IPv6_PREFERRED=$SYSCFG_dns_ipv6_preferred
    DNS_IPv6_ALTERNATE=$SYSCFG_dns_ipv6_alternate
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
        get_static_dns_ips lan
        if [ -z "$STATIC_DNS_IPv6" ] ; then
            # Get WAN static configuration.
            get_static_dns_ips wan
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

# Trim trailing spaces (Fixme: are there ever multiple trailing spaces? Or only one?)
while [ "$ips" != "${ips% }" ]
do
    ips="${ips% }"
done

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
