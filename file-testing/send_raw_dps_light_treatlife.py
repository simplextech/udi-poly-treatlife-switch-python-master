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

DEVICEID = "ebfc16d57ed374932cjqfk" #"ebfd4f4263bb769d99zjkq"  
DEVICEIP = "192.168.1.139" #"192.168.1.139" 
DEVICEKEY = "805217605357161b" #"ec0b2b581a246eab"   
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
# Show status of device
data = d.status()


# Generate the payload to send - add all the DPS values you want to change here
payload1=d.generate_payload(tinytuya.CONTROL, {'20': False, '22': 100, '23': 10,})
#time.sleep(1)
print('\nCurrent Status of Bulb: %r' % data)
time.sleep(2)
payload2=d.generate_payload(tinytuya.CONTROL, {'20': True, '22': 100, '23': 10,})
#time.sleep(1)
print('\nCurrent Status of Bulb: %r' % data)
#time.sleep(2)
payload3=d.generate_payload(tinytuya.CONTROL, {'20': True, '22': 1000, '23': 236,})
#time.sleep(1)
print('\nCurrent Status of Bulb: %r' % data)
# Send the payload to the device

d._send_receive(payload1)
time.sleep(2)
d._send_receive(payload2)
time.sleep(2)
d._send_receive(payload3)
#print('\nCurrent Status of Bulb: %r' % data)