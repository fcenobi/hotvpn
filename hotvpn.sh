#!/bin/bash
set -e

iptables=/sbin/iptables
ip=/sbin/ip

get_addr(){
	ip -4 addr show dev $1 | grep inet | head -n1 | awk '{print $2}'
}

get_net(){
	ip addr show dev $1 | grep inet | head -n1 | awk '{print $2}'
}

WAN=pia0
WAN_IP=$(get_addr $WAN)
WAN_NET=$(ip addr show dev $WAN | grep inet | head -n1 | awk '{print $4}')
LAN=wlan1
LAN_IP=$(get_addr $LAN)
LAN_NET=$(get_net $LAN)
NO_GO=wlan0
NO_GO_ALT=eth0
NO_GO_IP=$(get_addr $NO_GO)
NO_GO_NET=$(get_net $NO_GO)

RT_TABLE_ENTRY='100 hotvpn'

_install(){
	if grep -q $RT_TABLE_ENTRY /etc/iproute2/rt_tables; then
		echo 'table is already installed'
	else
		echo $RT_TABLE_ENTRY >> /etc/iproute2/rt_tables
	fi
	if [[ -e /etc/hostapd/hostapd.conf ]]; then
		echo "/etc/hostapd/hostapd.conf already exists"
		cp hostapd.conf /etc/hostapd/hostapd.conf.hotvpn
	else
		mkdir -p /etc/hostapd
		cp hostapd.conf /etc/hostapd/hostapd.conf
	fi
	if egrep -q '^[ \t]*conf-dir=';then
		conf_dir=$(egrep -q '^[ \t]*conf-dir=' | awk -F'=' '{print $2}')
	else
		conf_dir=/etc/dnsmasq.d
	fi
	if [[ -e ${conf_dir}/hotvpn.conf ]]; then
		echo "${conf_dir}/hotvpn.conf is already installed."
		cp hotvpn.dnsmasq $conf_dir/hotvpn.conf.new
	else
		mkdir -p $conf_dir
		cp hotvpn.dnsmasq $conf_dir/hotvpn.conf
	fi
}

_uninstall(){
	echo 'Removing routing table entry.'
	sed -i "/$RT_TABLE_ENTRY/d" /etc/iproute2/rt_tables

	if [[ -e /etc/hostapd/hostapd.conf ]]; then
		echo "Moving HostAP config to /etc/hostapd/hostapd.conf.hotvpn.uninsall"
		rm /etc/hostapd/hostapd.conf.hotvpn || echo -n
		mv /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.hotvpn.uninstall
	fi
	if egrep -q '^[ \t]*conf-dir=';then
		conf_dir=$(egrep -q '^[ \t]*conf-dir=' | awk -F'=' '{print $2}')
	else
		conf_dir=/etc/dnsmasq.d
	fi

	echo "Removing ${conf_dir}/hotvpn.conf*"
	rm ${conf_dir}/hotvpn.conf*
	echo "Stopping services."
	_stop
}


_start(){
	# Make sure we have the network interfaces up already
	if ! (ip addr show $LAN | grep -q inet) && ! (ip addr show $WAN | grep -q inet); then
		echo Network interfaces $LAN and $WAN must already be up.
		return 1
	fi

	# Setup NAT
	$iptables -t nat -A POSTROUTING -s $LAN_NET -o $WAN -j MASQUERADE
	$iptables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT
	$iptables -A FORWARD -i $LAN -o $WAN -j ACCEPT

	# Isolate the AP and VPN from the local network
	$iptables -A INPUT -i $NO_GO -s $WAN_NET -j DROP
	if [[ -n $NO_GO_ALT ]]; then
		$iptables -A INPUT -i $NO_GO_ALT -s $WAN_NET -j DROP
	fi

	# Add routes to the routing table
	$ip rule add from $LAN_NET table hotvpn
	$ip route add default dev $WAN table hotvpn
	$ip route add $LAN_NET dev $LAN table hotvpn

	# Enable IP forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Turn on the DHCP server
	/etc/init.d/dnsmasq start

	# Turn on the AP
	/etc/init.d/hostapd start
}

_stop(){
	# Disable IP forwarding
	echo 0 > /proc/sys/net/ipv4/ip_forward

	# Remove routes in the routing table
	$ip rule del from $LAN_NET table hotvpn
	$ip route del default dev $WAN table hotvpn
	$ip route del $LAN_NET dev $LAN table hotvpn

	# Tear down NAT
	$iptables -t nat -D POSTROUTING -s $LAN_NET -o $WAN -j MASQUERADE
	$iptables -D FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT
	$iptables -D FORWARD -i $LAN -o $WAN -j ACCEPT

	# Ditch isolation rules
	$iptables -D INPUT -i $NO_GO -s $WAN_NET -j DROP
	if [[ -n $NO_GO_ALT ]]; then
		$iptables -D INPUT -i $NO_GO_ALT -s $WAN_NET -j DROP
	fi

	# Turn off the DHCP server
	/etc/init.d/dnsmasq stop

	# Turn off the AP
	/etc/init.d/hostapd stop
}

case $1 in
	start)
		_start
		;;
	stop)
		_stop
		;;
	install)
		_install
		;;
	uninstall)
		_uninstall
		;;
	*)
		echo "$0 <start|stop|install|uninstall>"
esac
