#!/usr/bin/env python3

IPTABLES = '/sbin/iptables'
IP = '/sbin/ip'
TABLE_NAME = 'hotvpn'
RT_TABLE_ENTRY = '100 hotvpn'

import os
import subprocess

import NetworkManager



class NMIface:

	def __init__(self, iface):
		self.interface = iface
		self.device = None
		self.connection = None
		self._get_device_and_connection()

	@property
	def network(self):
		return '.'.join([str(x) for x in self.int_network])

	@property
	def int_network(self):
		network = [0]*4
		for octet in range(4):
			network[octet] = self.int_address[octet] & self.int_mask[octet]
		return network
	
	@property
	def int_mask(self):
		hex_mask = hex((0xffffffff << (32 - self.cidr )) & 0xffffffff)
		hex_mask = hex_mask.replace('0x', '')
		int_mask = [int(hex_mask[pos*2:(pos*2)+2], 16) for pos in range(4)]
		return int_mask

	@property
	def mask(self):
		return '.'.join(self.int_mask)
	
	@property
	def int_address(self):
		return [int(x, 10) for x in self.address.split('.')]

	def _get_device_and_connection(self):
		print('_get_device_and_connection')
		devices = NetworkManager.NetworkManager.Devices
		for device in devices:
			if device.Interface == self.interface:
					self.device = device
					self.cidr = device.Ip4Config.AddressData[0]['prefix']
					self.address = device.Ip4Config.AddressData[0]['address']

	@property
	def up(self):
		return self.device.State == NetworkManager.NM_DEVICE_STATE_ACTIVATED


class Config:
	no_go = ['wlan0', 'eth0']
	ap_iface = 'wlan1'
	vpn_iface = 'pia0'


def shell(*args, **kwargs):
	command_line = []
	args = list(args)
	if kwargs.get('_command'):
		command_line.insert(0, kwargs.pop('_command'))
	args.extend(kwargs_to_args(kwargs))
	command_line.extend(args)
	command = ' '.join(command_line)
	print(command)
	return subprocess.call(command_line)


def kwargs_to_args(kwargs):
	args = []
	for option, arg in kwargs.items():
		if len(option) > 1:
			option = '--{}'.format(option)
		else:
			option = '-{}'.format(option)
		args.append(option)
		if isinstance(arg, (str, int, float)):
			args.append(str(arg))
		elif hasattr(arg, '__iter__'):
			args.extend(arg)
	if 'args' in kwargs:
		positional_args = kwargs.pop('args')
		if positional_args:
			args.extend(positional_args)
	return args


def iptables(*args, **kwargs):
	command = '/sbin/iptables'
	kwargs['_command'] = command
	result = shell(*args, **kwargs)
	return result


def ip(*args, **kwargs):
	command = '/sbin/ip'
	kwargs['_command'] = command
	result = shell(*args, **kwargs)
	return result


def proc_set(path, value):
	with open(path, 'w') as proc_file:
		proc_file.write(str(value))


def all_up(config, ap, vpn):
	# Make sure we have the network interfaces up already
	if not ap.up or not vpn.up:
		raise OSError('Network interfaces {ap_iface} and {vpn_iface} must already be up.')
	enable_ip_forwarding()
	setup_iptables_rules(config, ap, vpn)
	setup_routes(config, ap, vpn)
	start_services(config, ap, vpn)


def enable_ip_forwarding():
	proc_set('/proc/sys/net/ipv4/ip_forward', 1)


def setup_iptables_rules(config, ap, vpn):
	# Setup NAT
	iptables(t='nat', A='POSTROUTING', s=ap.network, o=vpn.interface, j='MASQUERADE')
	iptables(A='FORWARD', i=vpn.interface, o=ap.interface, m='state', state='RELATED,ESTABLISHED', j='ACCEPT')
	iptables(A='FORWARD', i=ap.interface, o=vpn.interface, j='ACCEPT')
	# Isolate the AP and VPN from the local network
	for no_go in config.no_go:
		iptables(A='INPUT', i=no_go, s=vpn.network, j='DROP')


def setup_routes(config, ap, vpn):
	# Add routes to the routing table
	ip('route', 'add', 'default', 'dev', vpn.interface, 'table', TABLE_NAME)


def start_services(config, ap, vpn):
	# Turn on the DHCP server
	shell('/etc/init.d/dnsmasq', 'start')
	# Turn on the AP
	shell('/etc/init.d/hostapd', 'start')


def ap_start(config, ap, vpn):
	# Add routes to the routing table
	ip('rule', 'add', 'from', ap.network, 'table', TABLE_NAME)
	ip('route', 'add', ap.network, 'dev', ap.interface, 'table', TABLE_NAME)


def vpn_start(config, ap, vpn):
	pass


def ap_up(config, ap, vpn):
	ap_start(config, ap, vpn)
	if vpn.up:
		all_up(config, ap, vpn)
	if not vpn.up:
		print('vpn is down')


def vpn_up(config, ap, vpn):
	ap = NMIface(config.ap_iface)
	vpn = NMIface(config.vpn_iface)
	vpn_start(config, ap, vpn)
	if ap.up:
		all_up(config, ap, vpn)


def all_down(config, ap, vpn):
	if ap.up or vpn.up:
		raise OSError('Network interfaces {ap_iface} and {vpn_iface} must already be up.')
	disable_ip_forwarding()
	teardown_iptables_rules(config, ap, vpn)
	stop_services(config, ap, vpn)

def disable_ip_forwarding():
	# Disable IP forwarding
	proc_set('/proc/sys/net/ipv4/ip_forward', 0)


def teardown_iptables_rules(config, ap, vpn):
	# Tear down NAT
	iptables(t='nat', D='POSTROUTING', s=ap.network, o=vpn.interface, j='MASQUERADE')
	iptables(D='FORWARD', i=vpn.interface, o=ap.interface, m='state', state='RELATED,ESTABLISHED', j='ACCEPT')
	iptables(D='FORWARD', i=ap.interface, o=vpn.interface, j='ACCEPT')
	# Ditch isolation rules
	for no_go in config.no_go:
		iptables(D='INPUT', i=no_go, s=vpn.network, j='DROP')


def stop_services(config, ap, vpn):
	# Turn off the DHCP server
	shell('/etc/init.d/dnsmasq', 'stop')
	# Turn off the AP
	shell('/etc/init.d/hostapd', 'stop')


def vpn_stop(config, ap, vpn):
	vpn = NMIface(config.vpn_iface)
	ip('route', 'del', 'default', 'dev', vpn.interface, 'table', TABLE_NAME)


def ap_stop(config, ap, vpn):
	ap = NMIface(config.ap_iface)
	ip('rule', 'del', 'from', ap.network, 'table', TABLE_NAME)
	ip('route', 'del', ap.network, 'dev', ap.interface, 'table', TABLE_NAME)


def ap_down(config, ap, vpn):
	ap = NMIface(config.ap_iface)
	vpn = NMIface(config.vpn_iface)
	ap_stop(config, ap, vpn)
	if not vpn.up:
		all_down(config, ap, vpn)


def vpn_down(config, ap, vpn):
	ap = NMIface(config.ap_iface)
	vpn = NMIface(config.vpn_iface)
	vpn_stop(config, ap, vpn)
	if not ap.up:
		all_down(config, ap, vpn)


def handle_ifupdown():
	actions = {
		'pre-up': lambda *_: None, 
		'up': lambda *_: None, 
		'post-up': lambda *_: None, 
		'down': lambda *_: None,
		'pre-down': lambda *_: None,
		'post-down': lambda *_: None
		}
	ap_actions = actions.copy()
	ap_actions.update({'up': ap_up, 'down':ap_down})
	vpn_actions = actions.copy()
	vpn_actions.update({'up': vpn_up, 'down': vpn_down})
	config = Config()
	ap = NMIface(config.ap_iface)
	vpn = NMIface(config.vpn_iface)
	args = (config, ap, vpn)
	if config.ap_iface in os.environ:
		action = os.environ[config.ap_iface]
		ap_actions[action](*args)
	elif config.vpn_iface in os.environ:
		action = os.environ[config.vpn_iface]
		vpn_actions[action](*args)


if __name__ == '__main__':
	import sys
	handle_ifupdown()
	sys.exit(0)
