# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Example to send raw DPS values to Tuya devices

 You could also use set_value(dps_index,value) but would need to do that for each DPS value. 
 To send it in one packet, you build the payload yourself and send it using something simliar
 to this example.

 Note: Some devices will not accept multiple commands and require you to send two separate commands. 
 My Gosund dimmer switch is one of those and requires that I send two commands, 
 one for '1' for on/off and one for '3' for the dimmer. 

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

""" 
import tinytuya
import time
import os
import random

DEVICEID = "017743508caab5f0973e"
DEVICEIP = "192.168.1.137"
DEVICEKEY = "e779c96c964f71b2"
DEVICEVERS = "us"

# Check for environmental variables and always use those if available
DEVICEID = os.getenv("DEVICEID", DEVICEID)
DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

print("TinyTuya - Smart Bulb RGB Test [%s]\n" % tinytuya.__version__)
print('TESTING: Device %s at %s with key %s version %s' %
      (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))


# Connect to the device - replace with real values
d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
d.set_version(3.3)

# Generate the payload to send - add all the DPS values you want to change here
#if data != [0]
#payload=d.generate_payload(tinytuya.CONTROL, {'1': False, '2': 50})
#time.sleep(2)
#payload=d.generate_payload(tinytuya.CONTROL, {'1': True, '2': 50})
#time.sleep(2)

payload1=d.generate_payload(tinytuya.CONTROL, {'1': False, '2': 50})
payload2=d.generate_payload(tinytuya.CONTROL, {'1': True, '2': 50})

# Send the payload to the device

d._send_receive(payload1)
time.sleep(2)
d._send_receive(payload2)

# Get the status of the device
#response = requests.request("GET", url, headers=headers, data=payload)

#print(str(d._send_receive(payload)))

#Command for 
# Show status of device
data = d.status()
print('\nCurrent Status of Bulb: %r' % data)