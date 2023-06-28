from contextlib import closing
import telnetlib3 as telnetlib
import icmplib
import socket

import threading
import argparse
import signal
import time
import sys
import os

import json
#import ujson as json

from colorama import init, Fore, Back, Style
init(convert=True)

import Filters

c_ConfigFilePath = "Config.json"
c_SaveStateFilePath = "SaveState.json"

def CompleteExit():
	os.kill(os.getpid(), signal.SIGTERM)

class Address:
	Type = ""
	Mask = -1
	SubnetCount = 0
	AddressOctets = []

	def __init__(self, Address):
		if type(Address) == str:
			self.FromString(Address)
			self.CalculateLogistics()
		else:
			raise Exception("Invalid Address Type Given To Address Class")

	def IncrementAddress(self):
		self.AddressOctets[-1] += 1
		OctetsCount = len(self.AddressOctets)
		for _i in range(OctetsCount):
			i = OctetsCount - _i

			if self.AddressOctets[-i] > 0xFF:
				self.AddressOctets[-i] = 0
				if (i + 1) < OctetsCount:
					self.AddressOctets[-(i + 1)] += 1

	def FromString(self, AddressString):
		Address, *_Mask = AddressString.split("/")
		
		if "." in Address:
			# Assume IPv4
			self.Type = "IPv4"
			for Byte in Address.split("."):
				try:
					self.AddressOctets.append(int(Byte))
				except Exception:
					raise Exception("Invalid IPv4 Octet \"{}\"".format(Byte))

		elif ":" in Address:
			# Assume IPv6
			self.Type = "IPv6"
			Split = Address.split(":")
			for Word in Split:
				if len(Word) == 0:
					# We've Hit An "::", Add Null Octets
					for _ in range((8 - (len(Split) - 1)) * 2):
						self.AddressOctets.append(int(Byte))
					continue

				elif len(Word) < 4:
					# Add Missing Zeros
					Word = ("0" * (4 - len(Word))) + Word
				
				try:
					self.AddressOctets.append(int(Word[:2], 16))
					self.AddressOctets.append(int(Word[2:], 16))
				except Exception:
					raise Exception("Invalid IPv6 Word \"{}\"".format(Word))

		if len(_Mask) > 0:
			try:
				self.Mask = int(_Mask[0])
			except Exception:
				raise Exception("Invalid CIDR Mask")
		else:
			self.Mask = -1

	def CalculateLogistics(self):
		if self.Mask >= 0:
			if self.Type == "IPv4":
				self.SubnetCount = 2 ** (32 - self.Mask)
			elif self.Type == "IPv6":
				self.SubnetCount = 2 ** (128 - self.Mask)

	def ToString(self):
		Result = ""
		if self.Type == "IPv4":
			NotFirst = False
			for Octet in self.AddressOctets:
				Result += ((NotFirst and ".") or "") + str(Octet)
				NotFirst = True

		elif self.Type == "IPv6":
			# TODO
			pass
			#for Index in range(len(self.AddressOctets)/2):


		if self.Mask >= 0:
			Result += "/" + str(self.Mask)

		return Result




def BulkPing(Addresses, PingConfigs):
	AddressesCopy = Addresses.copy()
	States = {
		"Running": 0,
		"Pinged": 0
	}
	AliveHosts = []

	def PingAddressThread(Address):
		States["Running"] += 1
		try:
			Host = icmplib.ping(Address, count=PingConfigs["Count"], timeout=PingConfigs["Timeout"])
			States["Pinged"] += 1
			if Host.is_alive:
					AliveHosts.append(Host.address)
		except Exception as Error:
			print("Critical Error In PingAddressThread:", Error)
		finally:
			States["Running"] -= 1

	def PrintState():
		print(
			Fore.YELLOW
			+ "Pinging {0} Hosts({1} To {2}) {6}/{4}/{5}({3:.2f}%) {7} Running Threads     ".format(
				len(Addresses),
				Addresses[0], Addresses[-1],
				(States["Pinged"] / len(Addresses)) * 100.0,
				States["Pinged"], len(Addresses), len(AliveHosts),
				States["Running"]
			)
			+ Style.RESET_ALL,
			end="\r"
		)

	while len(AddressesCopy) > 0 or States["Running"] > 0:
		PrintState()
		if PingConfigs["ThreadPoolSize"] > States["Running"]:
			for _ in range(PingConfigs["ThreadPoolSize"] - States["Running"]):
				if len(AddressesCopy) <= 0:
					break
				threading.Thread(target=PingAddressThread, args=(AddressesCopy.pop(),)).start()
		time.sleep(0.01)

	PrintState()
	print()
	return AliveHosts

def CheckPort(Host, Port, Timeout=10):
	with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as Socket:
		Socket.settimeout(Timeout)
		if Socket.connect_ex((Host, Port)) == 0:
			return True
	return False

def BulkPortCheck(Addresses, Ports, PortCheckConfig):
	AddressesCopy = Addresses.copy()
	PortsCopy = Ports.copy()
	CurrentPort = PortsCopy.pop()
	States = {
		"Running": 0,
		"PortsChecked": 0,
		"OpenPorts": 0
	}
	HostsData = {}

	def PortCheckThread(Address, Port):
		States["Running"] += 1
		try:
			if not Address in HostsData:
					HostsData[Address] = []

			Result = CheckPort(Address, Port, Timeout=PortCheckConfig["Timeout"])
			if Result == True:
				HostsData[Address].append(Port)
				States["OpenPorts"] += 1
			States["PortsChecked"] += 1
			

		except Exception as Error:
			print("Critical Error In PortCheckThread:", Error)
		finally:
			States["Running"] -= 1

	def PrintState():
		print(
			Fore.YELLOW +
			"Checking {0} Ports For {1} Hosts {7}/{3}/{4}({2:.2f}%). Current Port: {5}. {6} Running Threads     ".format(
				len(Ports),
				len(Addresses),
				(States["PortsChecked"] / (len(Addresses) * len(Ports))) * 100.0,
				States["PortsChecked"], len(Addresses) * len(Ports),
				CurrentPort,
				States["Running"],
				States["OpenPorts"]
			)
			+ Style.RESET_ALL,
			end="\r"
		)

	while len(AddressesCopy) > 0 or len(PortsCopy) > 0 or States["Running"] > 0:
		PrintState()
		if PortCheckConfig["ThreadPoolSize"] > States["Running"]:
			for _ in range(PortCheckConfig["ThreadPoolSize"] - States["Running"]):
				if len(AddressesCopy) <= 0:
					if len(PortsCopy) <= 0:
						break
					AddressesCopy = Addresses.copy()
					CurrentPort = PortsCopy.pop()
				threading.Thread(target=PortCheckThread, args=(AddressesCopy.pop(), CurrentPort)).start()
		time.sleep(0.01)

	PrintState()
	print()

	return HostsData

def LoadState():
	SaveState = {
		"Hosts": [],
		"Ports": {},
		"OpenPorts": 0,
		"ScannedPorts": [],
		"CurrentAddress": "1.1.1.1"
	}
	if os.path.isfile(c_SaveStateFilePath):
		print(Fore.YELLOW + "Loading State..." + Style.RESET_ALL)
		File = open(c_SaveStateFilePath, "r+")
		SaveState = json.loads(File.read())
		File.close()
	return SaveState

def SaveState(SaveState):
	print(Fore.YELLOW + "Saving SaveState File..." + Style.RESET_ALL)
	File = open(c_SaveStateFilePath, "w+")
	File.write(json.dumps(SaveState))
	File.close()

def LoadConfig():
	Configs = {
		"AddressesPerIteration": 0xFF,
		"FilterCheckThreads": 80,
		"Ports": [],
		"PortCheck": {
			"ThreadPoolSize": 80,
			"Timeout": 10,
		},
		"Ping": {
			"ThreadPoolSize": 60,
			"Timeout": 5,
			"Count": 2
		}
	}
	if os.path.isfile(c_ConfigFilePath):
		print(Fore.YELLOW + "Found Config File, Loading Config..." + Style.RESET_ALL)
		File = open(c_ConfigFilePath, "r+")
		Configs = json.loads(File.read())
		File.close()
	else:
		print(Fore.RED + "No Exsiting Config File \"{}\", Creating A New One...".format(c_ConfigFilePath))
		File = open(c_ConfigFilePath, "w+")
		File.write(json.dumps(Configs))
		File.close()
	return Configs


def AddFoundTargets(Hosts, SaveState):
	for Key in Hosts:
		if len(Hosts[Key]) > 0:
			SaveState["Ports"][Key] = Hosts[Key]
			SaveState["OpenPorts"] += len(Hosts[Key])
			print(Fore.CYAN + "{} => {} Added".format(Key, Hosts[Key]) + Style.RESET_ALL)

def FilterHostsPorts(NewPorts, OldPorts, HostList, OldHostPortData, PortCheckConfig):
	OldPorts.sort()
	NewPorts.sort()
	OpenPorts = 0

	if NewPorts != OldPorts and len(HostList) > 0:
		print(Fore.RED + "Scan Ports Config Changed(Old: {}, New: {}), Re-Scanning Hosts...".format(OldPorts, NewPorts) + Style.RESET_ALL)
		

		# Reuse As Many Ports As You Can
		NewPortsData = {}
		for Host in OldHostPortData:
			for Port in NewPorts:
				if Port in OldHostPortData[Host]:
					if not Host in NewPortsData:
						NewPortsData[Host] = []
					NewPortsData[Host].append(Port)
					OpenPorts += 1

		print(Fore.YELLOW + "Reused {} Open Ports".format(OpenPorts) + Style.RESET_ALL)

		NewPortList = []
		for Port in NewPorts:
			if not Port in OldPorts:
				NewPortList.append(Port)
		
		if len(NewPortList) > 0:
			print(Fore.YELLOW + "Filtering Ports: {}".format(NewPortList) + Style.RESET_ALL)

			Hosts = BulkPortCheck(HostList, NewPortList, PortCheckConfig)
			for Host in Hosts:
				if len(Hosts[Host]) > 0:
					if not Host in NewPortsData:
						NewPortsData[Host] = []
					for Port in Hosts[Host]:
						NewPortsData[Host].append(Port)
					OpenPorts += 1
		print(Fore.GREEN + "Finished Port Re-Scan" + Style.RESET_ALL)
		return OpenPorts, NewPortsData
	return False, False

def RunFilterForHost(Host, Ports, Filters):
	Results = {}
	for Port in Ports:
		if Port in Filters:
			Results[Port] = Filters[Port](Host)
		else:
			Results[Port] = "UNK"
	return [Host, Results]


def RunFilters(HostsAndPorts, Threads):
	HostsAndPortsCopy = HostsAndPorts.copy()
	States = {
		"Running": 0,
		"Done": 0
	}
	Results = []

	def RunFilterForHostWrapper(Host, Ports, Filters):
		States["Running"] += 1
		Results.append(RunFilterForHost(Host, Ports, Filters))
		States["Running"] -= 1
		States["Done"] += 1

	def PrintState():
		print(
			Fore.YELLOW +
			"Filtering {0}/{1}({2:.2f}%) Hosts. {3} Running Threads     ".format(
				States["Done"],
				len(HostsAndPorts),
				(States["Done"] / len(HostsAndPorts)) * 100.0,
				States["Running"]
			)
			+ Style.RESET_ALL,
			end="\r"
		)

	while len(HostsAndPortsCopy) > 0 or States["Running"] > 0:
		PrintState()
		if Threads > States["Running"]:
			for _ in range(Threads - States["Running"]):
				if len(HostsAndPortsCopy) <= 0:
					break
				Index = list(HostsAndPortsCopy.keys())[0]
				Ports = HostsAndPortsCopy.pop(Index)
				threading.Thread(target=RunFilterForHostWrapper, args=(Index, Ports, Filters.c_Filters)).start()
		time.sleep(0.01)
	PrintState()
	return Results


def main():
	g_ArgParser = argparse.ArgumentParser(
		prog="PortScanner",
		description="PortScanner pings hosts, and scans for open ports"
	)
	g_ArgParser.add_argument("-f", "--filter", dest="Filter", required=False, help="Filters Collected Ports And Prints", action="store_true")
	g_ArgParser.add_argument("-fp", "--filterports", dest="FilterPorts", metavar="PORTS", required=False, help="Sets the ports to use when filtering (Separated by space)", nargs="+", type=int)
	g_ArgParser.add_argument("-fc", "--filtercheck", dest="FilterCheck", required=False, help="If set uses the filters defined in \"Filters.py\" for extra host detection.", action="store_true")
	g_ArgParser.add_argument("-fma", "--filtermatchall", dest="FilterMatchAll", required=False, help="If set the address will need to match all ports before being printed", action="store_true")
	g_ArgParser.add_argument("-irs", "--ignorerescan", dest="IgnorePortReScan", required=False, help="If set does not execute the re-scan if ports changed.", action="store_true")
	#g_ArgParser.add_argument("-t", "--addresstype", dest="AddressType", required=False, choices=["IPv4", "IPv6"], default="IPv4", help="Type of address used. If this option isn't set the script will try to detect the type using provided data. (Default: IPv4)")
	g_Arguments = g_ArgParser.parse_args()

	g_Configs = LoadConfig()
	g_SaveState = LoadState()
	g_CurrentAddress = Address(g_SaveState["CurrentAddress"])
	g_Addresses = []
	g_MainLoop = True
	print(Fore.BLUE + "Current Configs: {}".format(g_Configs) + Style.RESET_ALL)
	print(Fore.BLUE + "Current Arguments: {}".format(g_Arguments) + Style.RESET_ALL)

	if g_Arguments.Filter:
		print(Fore.YELLOW + "Filtering Hosts..." + Style.RESET_ALL)
		FilterPorts = g_Arguments.FilterPorts
		MatchAll = g_Arguments.FilterMatchAll

		HostsAndPorts = {}

		for HostAddress in g_SaveState["Ports"]:
			HostPorts = g_SaveState["Ports"][HostAddress]
			Passed = False
			for Port in FilterPorts:
				if MatchAll and (not Port in HostPorts):
					Passed = False
					break
				elif Port in HostPorts:
					Passed = True

			if Passed:
				if g_Arguments.FilterCheck:
					HostsAndPorts[HostAddress] = HostPorts
				else:
					print(Fore.CYAN + "{} => {}".format(HostAddress, HostPorts) + Style.RESET_ALL)
		if g_Arguments.FilterCheck and len(HostsAndPorts) > 0:
			Results = RunFilters(HostsAndPorts, g_Configs["FilterCheckThreads"])
			for Result in Results:
				print(Fore.CYAN + Result[0] + Style.RESET_ALL)
				Ports = Result[1]
				for Port in Ports:
					print(Fore.CYAN + "\t{}: {}".format(Port, Ports[Port]) + Style.RESET_ALL)


		CompleteExit()

	if not g_Arguments.IgnorePortReScan:
		ResultOpenPorts, ResultHosts = FilterHostsPorts(g_Configs["Ports"], g_SaveState["ScannedPorts"], g_SaveState["Hosts"], g_SaveState["Ports"], g_Configs["PortCheck"]) or g_SaveState["OpenPorts"]
		if ResultOpenPorts != False and ResultHosts != False:
			g_SaveState["OpenPorts"] = ResultOpenPorts
			g_SaveState["Ports"] = ResultHosts
		g_SaveState["ScannedPorts"] = g_Configs["Ports"]

	while g_MainLoop:
		Iteration = 0
		try:
			for i in range(0xFFFF_FFFF):
				g_Addresses.append(g_CurrentAddress.ToString())
				if len(g_Addresses) >= g_Configs["AddressesPerIteration"]:
					AliveHosts = BulkPing(g_Addresses, g_Configs["Ping"])
					if len(AliveHosts) > 0:

						for Host in AliveHosts:
							g_SaveState["Hosts"].append(Host)

						AddFoundTargets(BulkPortCheck(AliveHosts, g_Configs["Ports"], g_Configs["PortCheck"]), g_SaveState)
					
					g_SaveState["CurrentAddress"] = g_CurrentAddress.ToString()
					g_Addresses = []

					if Iteration % 5 == 0:
						SaveState(g_SaveState)
					
					Iteration += 1
				g_CurrentAddress.IncrementAddress()
		except KeyboardInterrupt:
			print(Fore.MAGENTA + "\n\nKeyboardInterrupt, Hosts: {}, Open Ports: {}, Final Address: {}".format(len(g_SaveState["Hosts"]), g_SaveState["OpenPorts"], g_CurrentAddress.ToString()) + Style.RESET_ALL)
			g_MainLoop = False
		except Exception as Error:
			print(Style.BRIGHT + Back.BLUE + Fore.WHITE + "Exception: {}".format(Error) + Style.RESET_ALL)
			print(Style.BRIGHT + Back.BLUE + Fore.WHITE + "Restarting In 5 Seconds..." + Style.RESET_ALL)
			SaveState(g_SaveState)
			g_SaveState = LoadState()
			time.sleep(5)

	SaveState(g_SaveState)
	print(Fore.YELLOW + "SaveState Saved, Forcefully Stopping Threads..." + Style.RESET_ALL)
	CompleteExit()
			



if __name__ == "__main__":
	main()