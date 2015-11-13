#!/usr/bin/env python3


import NetworkManager


class NMIface:

	def __init__(self, iface):
		self.interface = iface

	@property
	def network(self):
		address_data = self.get_address_data()
		addr = [int(x, 10) for x in address_data[0].split('.')]
		mask = address_data[1]
		network = [0]*4
		for octet in range(4):
			network[octet] = addr[octet] & mask[octet]
		return network

	def get_address_data(self):
		active_connections = NetworkManager.NetworkManager.ActiveConnections
		for connection in active_connections:
			for device in connection.Devices:
				if device.Interface == self.interface:
					return connection.Ip4Config.AddressData


class Config:

	ap_iface = 'wlan1'
	vpn_iface = 'pia0'

