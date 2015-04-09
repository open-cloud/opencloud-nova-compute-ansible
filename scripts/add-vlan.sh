#!/bin/sh

IFACE=$1
VLAN=$2

ifconfig "$IFACE"."$VLAN" 2>&1 > /dev/null
if [ "$?" -ne 0 ]
then
    ifconfig "$IFACE" up
    vconfig add "$IFACE" "$VLAN"
    ifconfig "$IFACE"."$VLAN" up
fi
