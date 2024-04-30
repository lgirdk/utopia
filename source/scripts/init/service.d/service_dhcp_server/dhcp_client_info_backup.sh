#!/bin/sh

calculate_checksum() {
    filename=$1
    checksum=$(busybox md5sum "$filename" | awk '{print $1}')
    echo $checksum
}

copy_file() {
    source_file=$1
    dest_file=$2

    source_checksum=$(calculate_checksum "$source_file")
    dest_checksum=$(calculate_checksum "$dest_file")

    if [ "$source_checksum" != "$dest_checksum" ]; then
        cp "$source_file" "$dest_file"
    fi
}

exec 200>"/tmp/.dnsmasq_leases_lock" || exit 1
flock -n "200" || exit 1
copy_file "/var/lib/misc/dnsmasq.leases" "/nvram/dnsmasq.leases"
copy_file "/var/lib/misc/dnsmasq.options" "/nvram/dnsmasq.options"
flock -u 200
