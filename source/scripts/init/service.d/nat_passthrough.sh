#!/bin/sh

#NAT passthrough ,MNG 

bridge_mode="$(syscfg get bridge_mode)"
natPassthrough_enable="$(syscfg get natPassthrough_enable)"

# get the NAT Passthrough client configuration early, it may be used
# in various parts of the script.
# total_client_count is all the NPT clients, but not all may be enabled.
# client_count and client_macs refer only to enabled clients.
total_client_count="$(syscfg get mngFWNATPassthroughCount)"
[ -n "$total_client_count" ] || total_client_count=0
client_count=0
client_macs=""
if [ "$total_client_count" != 0 ] && [ "$natPassthrough_enable" != 0 ]; then
    for i in $(seq 1 $total_client_count); do
        name=$(syscfg get "mngFWNATPassthrough_$i")
        if [ -z "$name" ]; then
            echo "WARNING: NAT Passthrough client index $i has no name"
            continue
        fi
        if [ "$(syscfg get "$name" enable)" = "1" ]; then
            mac=$(syscfg get "$name" mac)
            if [ -z "$mac" ]; then
                echo "WARNING: NAT Passthrough client $name has no configured MAC address"
                continue
            fi
            client_macs="$client_macs $mac"
            let "client_count++"
	echo $client_count
        fi
    done
    unset i name enable
fi

# static ebtables rules which are created once at boot (or when NAT passthrough
# is first enabled) and then not touched.
# No specific MAC addresses go into the base INPUT/OUTPUT/FORWARD chains, we only
# link to nat_passthrough specific ebtables chains when filtering NAT PT MACs.
#
# Don't forget to delete rules added here in service_stop
init_ebtables()
{
    # new chains to filter NAT passthrough based on MAC
    ebtables -N nat_passthrough_to_host -P RETURN
    ebtables -N nat_passthrough_from_host -P RETURN
    ebtables -N nat_passthrough_to_lan -P DROP
    ebtables -N nat_passthrough_from_lan -P DROP
    refresh_ebtables
}

# Update the nat_passthrough ebtables chains
# Caution! Calling this function when the $NP_IFNAME interface is up,
# may cause unwanted communication between the Atom and NPT clients
refresh_ebtables()
{
    echo " refresh_ebtables  "
    ebtables -F nat_passthrough_to_lan
    ebtables -F nat_passthrough_from_lan
    ebtables -F nat_passthrough_to_host
    ebtables -F nat_passthrough_from_host

    local mac
    for mac in $client_macs; do
        ebtables -A nat_passthrough_to_lan -d $mac -j ACCEPT
        ebtables -A nat_passthrough_from_lan -s $mac -j ACCEPT
        ebtables -A nat_passthrough_to_host -s $mac -p 0x888e -j ACCEPT
        ebtables -A nat_passthrough_to_host -s $mac -j DROP
        ebtables -A nat_passthrough_from_host -d $mac -j DROP
    done
}

service_start()
{
    if [ "$bridge_mode" != 0 ] || [ "$client_count" = 0 ]; then
        # nothing to do
        return 0
    fi

    init_ebtables
    sysevent set firewall-restart
}

service_stop()
{
    echo "*** Stopping MNG NAT Passthrough ***"

    # delete the ebtables rules created by init_ebtables()
 
    ebtables -X nat_passthrough_to_host
    ebtables -X nat_passthrough_from_host
    ebtables -X nat_passthrough_to_lan
    ebtables -X nat_passthrough_from_lan

    sysevent set firewall-restart
}

service_reload()
{
    if [ "$bridge_mode" != "0" ] || [ "$natPassthrough_enable" = 0 ]; then
        # bridge mode and NAT Passthrough don't coexist, if we're restarting
        # and bridge mode is on, disable this service.
        # Drop stderr because if NPT never started, service_stop will print
        # errors about deleting nonexistent things
        service_stop 2>/dev/null
        return 0
    fi

        if [ "$client_count" = 0 ]; then
            # NPT was never started and the client count is still zero: do nothing
            return 0
        else
            # NPT was never started but now we need to add some clients: do a full start
            service_start
        fi
}

case "$1" in
    start|restart)
        # start and restart are really the same thing. service_reload
        # will call service_start (or maybe even service_stop) if necessary
        service_reload
        ;;
    stop)
        service_stop
        ;;

    # full-start and full-restart are for debugging only!
    # Don't call these from other code
    full-start)
        service_start
        ;;
    full-restart)
        service_stop && service_start
        ;;
    *)
        echo "Usage: $0 [ start | stop | restart ]"
        exit 3
        ;;
esac
