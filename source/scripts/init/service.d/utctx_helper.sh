#!/bin/sh

get_utctx_val() {
    queries=$1
    output="$(utctx_cmd get $queries)"
    queries=(${queries})
    IFS="'"; read -a output <<< "$output"; IFS=' '
    len=${#queries[@]}
    for (( i=0; i<$len; i++ ))
    do
        export "SYSCFG_${queries[$i]/'::'/_}=${output[$i]}"
    done
}
