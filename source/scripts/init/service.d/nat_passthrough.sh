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

    if [ ! -d /sys/class/net/brlan0/bridge/ ]; then
        echo "ERROR: bridge brlan0 doesn't exists"
        return 1
    else
        if [ -d /sys/class/net/lbr0/brport ]; then
            echo "WARNING: interface lbr0 is already in a bridge"
        else
            # connect lbr0 interface to brlan0 bridge.
            brctl addif brlan0 lbr0
        fi
    fi

    # new chains to filter NAT passthrough based on MAC
    ebtables -N nat_passthrough_from_host -P RETURN
    err=$?
    # If the chains are already present no need to duplicate it again
    if [ $err -eq 0 ]; then
        ebtables -N nat_passthrough_to_host -P RETURN
        ebtables -N nat_passthrough_to_lan  -P RETURN

        ebtables -t filter -A FORWARD -i l2sd0.100 -j nat_passthrough_from_host
        ebtables -t filter -A FORWARD -o l2sd0.100 -j nat_passthrough_to_host
        ebtables -t filter -A FORWARD -i lbr0 -j DROP
        ebtables -t filter -A FORWARD -o lbr0 -j DROP

        ebtables -t filter -A INPUT   -j nat_passthrough_to_lan
    fi

    refresh_ebtables
    return 0
}

refresh_ebtables()
{

    ebtables -F nat_passthrough_from_host
    ebtables -F nat_passthrough_to_host
    ebtables -F nat_passthrough_to_lan

    local mac
    for mac in $client_macs; do
        ebtables -A nat_passthrough_from_host -s $mac -j ACCEPT
        ebtables -A nat_passthrough_to_host   -d $mac -j ACCEPT
        ebtables -A nat_passthrough_to_lan    -s $mac -j DROP
        ebtables -A nat_passthrough_to_lan    -d $mac -j DROP
    done

}

service_start()
{
    echo "*** Starting MNG NAT Passthrough ***"

    if [ "$bridge_mode" != 0 ] || [ "$client_count" = 0 ]; then
        # nothing to do
        return 0
    fi

    init_ebtables
    res=$?
    if [ $res -eq 0 ]; then
        sysevent set firewall-restart
    fi
}

service_stop()
{
    echo "*** Stopping MNG NAT Passthrough ***"

    ebtables -F nat_passthrough_from_host
    ebtables -F nat_passthrough_to_host
    ebtables -F nat_passthrough_to_lan

    ebtables -t filter -D FORWARD -i l2sd0.100 -j nat_passthrough_from_host
    ebtables -t filter -D FORWARD -o l2sd0.100 -j nat_passthrough_to_host
    ebtables -t filter -D FORWARD -i lbr0 -j DROP
    ebtables -t filter -D FORWARD -o lbr0 -j DROP
    ebtables -t filter -D INPUT   -j nat_passthrough_to_lan

    # Delete the custom chains
    ebtables -X nat_passthrough_from_host
    ebtables -X nat_passthrough_to_host
    ebtables -X nat_passthrough_to_lan

    # If not in bridge mode then delete lbr0 interface from the bridge
    if [ "$bridge_mode" = "0" ] && [ -d /sys/class/net/brlan0/bridge ]
    then
        brctl delif brlan0 lbr0
    fi

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
