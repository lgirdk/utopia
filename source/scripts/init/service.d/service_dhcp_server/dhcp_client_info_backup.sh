#!/bin/sh

copy_file() {
	source_file="$1"
	dest_file="$2"

	if ! cmp -s "$source_file" "$dest_file"
	then
		if [ -f "$source_file" ]
		then
			cp "$source_file" "$dest_file"
		fi
	fi
}

exec 200>"/tmp/.dnsmasq_leases_lock" || exit 1
flock -n "200" || exit 1
copy_file "/var/lib/misc/dnsmasq.leases" "/nvram/dnsmasq.leases"
copy_file "/var/lib/misc/dnsmasq.options" "/nvram/dnsmasq.options"
flock -u 200
