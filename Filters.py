from contextlib import closing
import telnetlib3 as telnetlib
import socket
import asyncio
import time


def TestHostTelnet(Host, OutputData):
	try:
		async def TelnetShell(Reader, Writer):
			while True:
				Output = await Reader.read(1024)
				if not Output:
					break
				else:
					OutputData.append([Host, Output])
					Reader.close()

		asyncio.run(telnetlib.open_connection(Host.address, 23, shell=TelnetShell))
	except Exception:
		OutputData.append([Host, False])

def OnRTSP(Address):
	Data = {"IsRTSP": False}

	asyncio.set_event_loop(asyncio.new_event_loop())

	try:
		async def TelnetShell(Reader, Writer):
			Writer.write("\r\nOPTIONS rtsp://{}:554 RTSP/1.0".format(Address))
			Writer.write("\r\n")
			print("sent")
			Output = await Reader.read(32)
			print("recv", Output)
			if Output.startswith("RTSP/1.0 200 OK"):
				Data["IsRTSP"] = True
			Reader.close()
			Writer.close()

		Loop = asyncio.get_event_loop()
		Reader, Writer = Loop.run_until_complete(telnetlib.open_connection(Address, 554, shell=TelnetShell))
		Loop.run_until_complete(Writer.protocol.waiter_closed)
	except Exception as Error:
		print(Error)
		pass

	if Data["IsRTSP"]:
		return "554(RTSP) OPEN"
	else:
		return "554(RTSP) CLOSED"



c_Filters = {
	554: OnRTSP,
}
print(OnRTSP("131.247.210.30"))
print("so it's done huh?")
#OPTIONS rtsp://131.247.210.30 RTSP/1.0