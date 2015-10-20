#!/bin/bash
set -e

ip_parse=$(dirname "$(readlink -f $0)")/ip_parse

WAN_UUID=49ae9ddb-430e-4ca5-b4be-77e74d6e6ee2
WAN=pia0
WAN_IP=$($ip_parse $WAN address 4)
WAN_NET=$($ip_parse $WAN network 4)
LAN=wlan1
LAN_IP=$($ip_parse $LAN address 4)
LAN_NET=$($ip_parse $LAN network 4)

declare -a NO_GO=( wlan0 eth0 )

RT_TABLE_ENTRY='100 hotvpn'


iptables=/sbin/iptables

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

_add_routes(){
	set +e
	set -x
	# Add routes to the routing table
	ip rule add from $LAN_NET table hotvpn
	ip route add default dev $WAN table hotvpn
	ip route add $LAN_NET dev $LAN table hotvpn
}


_start(){
	set -x
	# Make sure we have the network interfaces up already
	if ! (ip addr show $LAN | grep -q inet); then
		echo Network interfaces $LAN must already be up.
		return 1
	fi
	sudo -u $SUDO_USER nmcli connection up $WAN_UUID || echo -n

	# Setup NAT
	$iptables -t nat -A POSTROUTING -s $LAN_NET -o $WAN -j MASQUERADE
	$iptables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT
	$iptables -A FORWARD -i $LAN -o $WAN -j ACCEPT

	# Isolate the AP and VPN from the local network
	for iface in $NO_GO; do
		$iptables -A INPUT -i $iface -s $WAN_NET -j DROP
	done

	_add_routes

	set +x
	# Enable IP forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Turn on the DHCP server
	/etc/init.d/dnsmasq start

	# Turn on the AP
	/etc/init.d/hostapd start

	_add_routes

}

_stop(){
	# Disable IP forwarding
	echo 0 > /proc/sys/net/ipv4/ip_forward

	if ! (ip addr show $LAN | grep -q inet) || ! (ip addr show $WAN | grep -q inet); then
		set +e
		echo "WARN: Missing an interface."
		set -x
	fi

	# Remove routes in the routing table
	ip route flush table hotvpn
	# Tear down NAT
	$iptables -t nat -D POSTROUTING -s $LAN_NET -o $WAN -j MASQUERADE
	$iptables -D FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT
	$iptables -D FORWARD -i $LAN -o $WAN -j ACCEPT

	# Ditch isolation rules
	for iface in $NO_GO; do
		$iptables -D INPUT -i $iface -s $WAN_NET -j DROP
	done
	set +x
	set -e

	# Turn off the DHCP server
	/etc/init.d/dnsmasq stop

	# Turn off the AP
	/etc/init.d/hostapd stop

	nmcli connection down $WAN
}

case $1 in
	start)
		_start
		;;
	stop)
		_stop
		;;
	force-routes)
		_add_routes
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
