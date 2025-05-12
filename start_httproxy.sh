#!/bin/bash
declare upstreams
declare listen_ports
declare listen_addr
declare listen_host


function init(){
    read -ra upstreams <<< "$UPSTREAMS"
    read -ra listen_ports <<< "$LISTEN_PORTS"
    listen_addr=$LISTEN_ADDR
    listen_host=$LISTEN_HOST
}

function check(){
    [ ${#upstreams[@]} -eq 0 ] && echo "UPSTREAMS should NOT be empty" && exit 1
    [ ${#listen_ports[@]} -eq 0 ] && echo "LISTEN_PORTS should NOT be empty" && exit 1
    [ ${#upstreams[@]} != ${#listen_ports[@]} ] && echo "UPSTREAMS should match LISTEN_PORTS" && exit 1
    [ -z $listen_addr ] && echo "LISTEN_ADDR is NOT valid" && exit 1
}

function start(){
    cmd="httproxy"
    for index in "${!upstreams[@]}"; do
        upstream=${upstreams[$index]}
        listen_port=${listen_ports[$index]}
        cmd+=" -u $upstream -p $listen_port"
    done
    cmd+=" -b $LISTEN_ADDR"
    [ -z $listen_host ] || cmd+=" -o $listen_host"
    echo "Start using cmd: \"$cmd\""
    eval $cmd
}

function main(){
    init
    check
    start
}

main
#<<<END
