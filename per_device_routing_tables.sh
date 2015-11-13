#!/bin/sh

# Run
# chown root:root per_device_routing_tables.sh
# chmod 700 per_device_routing_tables.sh
#
# or NM will refuse to run the script.
# Then move the script to /etc/NetworkManager/dispatcher.d

export PATH="/bin:/sbin:/usr/bin:/usr/sbin"

#LOG="/var/log/$(basename $0).log"
#echo -e "\n========== $(date)\n'$1' '$2'\n$(env)" >> $LOG

case $2 in
	up|dhcp4-change)
		# Add one line per device in /etc/iproute2/rt_tables, like this:
		# 100 eth0
		# 101 wlan0
		# 102 ppp0
		# 103 usb0

		if [ "$(awk '/^[^#]/ { if ( $2 == "'$DEVICE_IP_IFACE'" ) { print $2 } }' /etc/iproute2/rt_tables)" != "" ]
		then
			IP_PREFIX=$(echo $IP4_ADDRESS_0 | cut -d ' ' -f 1 | cut -d / -f 2)
			#echo "ip route add $DHCP4_NETWORK_NUMBER/$IP_PREFIX dev $DEVICE_IP_IFACE src $DHCP4_IP_ADDRESS table $DEVICE_IP_IFACE" >> $LOG
			#echo "ip route add $DHCP4_NETWORK_NUMBER/$IP_PREFIX dev $DEVICE_IP_IFACE src $DHCP4_IP_ADDRESS" >> $LOG
			#echo "ip route add default via $(echo $DHCP4_ROUTERS | cut -d ' ' -f 1) table $DEVICE_IP_IFACE" >> $LOG
			#echo "ip rule add from $DHCP4_IP_ADDRESS table $DEVICE_IP_IFACE" >> $LOG

			ip route add $DHCP4_NETWORK_NUMBER/$IP_PREFIX dev $DEVICE_IP_IFACE src $DHCP4_IP_ADDRESS table $DEVICE_IP_IFACE
			ip route add $DHCP4_NETWORK_NUMBER/$IP_PREFIX dev $DEVICE_IP_IFACE src $DHCP4_IP_ADDRESS
			ip route add default via $(echo $DHCP4_ROUTERS | cut -d ' ' -f 1) table $DEVICE_IP_IFACE
			ip rule add from $DHCP4_IP_ADDRESS table $DEVICE_IP_IFACE
		fi

		/bin/true
	;;

	down)
		if [ "$(awk '/^[^#]/ { if ( $2 == "'$1'" ) { print $2 } }' /etc/iproute2/rt_tables)" != "" ]
		then
			ip rule del table $1
		fi
	;;

	*)
	exit 0
	;;
esac
