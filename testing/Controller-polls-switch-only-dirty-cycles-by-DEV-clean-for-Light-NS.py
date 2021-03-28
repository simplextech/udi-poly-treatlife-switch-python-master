### Original Beautiful Code by Jason Cox #
### Code Hacked by Steve Bailey for a Polyglot Node Server on Universal Devices ISY #############

####### Used to create controller and single node class for TreatLife product to polyinterface  #
# This adds api and secert to custom parameters then polls Switches  Most in test Node Server   #

# TreatLife Device Wizard
# -*- coding: utf-8 -*-
# Modules
import requests
import time
import os
import random
import hmac
import hashlib
import json
import pprint
import logging
import tinytuya 
# Backward compatability for python2
try:
    input = 'Yes'
except NameError:
    pass
########################################################################################### TOKEN AUTHENTICATION ################################################################################################################
def tuyaPlatform(apiRegion, apiKey, apiSecret, uri, token=None):
    url = "https://openapi.tuya%s.com/v1.0/%s" % (apiRegion,uri)
    now = int(time.time()*1000)
    if(token==None):
        payload = apiKey + str(now)
    else:
        payload = apiKey + token + str(now)
    print("API Key ", apiKey)
    print("Token ", payload)

    # Sign Payload
    signature = hmac.new(
        apiSecret.encode('utf-8'),
        msg=payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

    # Create Header Data
    headers = {}
    headers['client_id'] = apiKey
    headers['sign_method'] = 'HMAC-SHA256'
    headers['t'] = str(now)
    headers['sign'] = signature
    if(token != None):
        headers['access_token'] = token

    # Get Token
    response = requests.get(url, headers=headers)
    try:
        response_dict = json.loads(response.content.decode())
    except:
        try:
            response_dict = json.loads(response.content)
        except:
            print("Failed to get valid JSON response")

    return(response_dict)
    
    
def wizard(color=True):
########################################################################################### CUSTOM PARAMETERS ##################################################################################################################
####################################### Loads as custom parameters in Node Server ###############################
    
    config = {}
    config['apiKey'] = "txejpdfda9iwmn5cg2es"
    config['apiSecret'] = "46d6072ffd724e0ba5ebeb5cc6b9dce9"
    config['apiRegion'] = 'us'
    config['apiDeviceID'] = "017743508caab5f0973e"
    needconfigs = True
       
    print('')
    print('TreatLife Device Discovery')  
    print('') 
    print('Authentication' + ' [%s]' % (tinytuya.version))  ##print## 2
    
    if(config['apiKey'] != '' and config['apiSecret'] != '' and
            config['apiRegion'] != '' and config['apiDeviceID'] != ''):
        needconfigs = False
        answer = 'Y' #input(subbold + '    Use existing credentials ' +
                  #     normal + '(Y/n): ')
        if('Y'[0:1].lower() == 'n'):
            needconfigs = True

    
    KEY = config['apiKey']
    SECRET = config['apiSecret']
    DEVICEID = config['apiDeviceID']
    REGION = config['apiRegion']        # us, eu, cn, in
    LANG = 'us'                         # en or zh

    # Get Oauth Token from tuyaPlatform
    uri = 'token?grant_type=1'
    response_dict = tuyaPlatform(REGION, KEY, SECRET,uri)
    token = response_dict['result']['access_token']

    # Get UID from sample Device ID 
    uri = 'devices/%s' % DEVICEID
    response_dict = tuyaPlatform(REGION, KEY, SECRET, uri, token)
    uid = response_dict['result']['uid']
    print(uid)

    # Use UID to get list of all Devices for User
    uri = 'users/%s/devices' % uid
    json_data = tuyaPlatform(REGION, KEY, SECRET, uri, token)
    #print("Full json above", json_data)

    # Filter to only Name, ID and Key
    tuyadevices = []
    for i in json_data['result']:
        item = {}
        item['name'] = i['name'].strip()
        item['id'] = i['id']
        item['key'] = i['local_key']
        item['ip'] = i['ip']           ####Added IP
        tuyadevices.append(item)

    # Display device list
    print("\n\n" + "Device Listing\n")
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    print("\n\n" + "Hello Here's are the Devices with INTERNET ACTIVE IP ADDRESSES \n\n " + output)  
    
######################### Device Switch Poller ###################################
#                                                                                #
# Using devId to poll Switches with lights or should i use key length??????####
#                                                                                #
# NEED TO GRAB SWITCH DEVICES AND MAKE THEM SEPARATE NODES FOR EACH SWITCH/LIGHT #
#                                                                                #
######################### By-Pass Data Input #####################################
    
    if('Y'[0:1].lower() != 'n'):
        # Scan network for devices and provide polling data
        ###print(normal + "\nScanning local network for Tuya devices...")
        devices = tinytuya.deviceScan(False, 20) #### changed 20 to 1
        #print("    %s%s local devices discovered%s" %
        #      ( len(devices)))
        print("")

        def getIP(d, gwid):
            for ip in d:
                if (gwid == d[ip]['gwId']):
                    return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("Polling TreatLife Devices...\n")  
        for i in tuyadevices:
            item = {}
            name = i['name']
            (ip, ver) = getIP(devices, i['id'])  ## 'id'
            item['name'] = name
            item['ip'] = ip
            item['ver'] = ver
            item['id'] = i['id']
            item['key'] = i['key']
            if (ip == 0):
                #print("    %s[%s] - %s%s - %sError: No IP found%s" %
                #      (name, ip, alert, normal))
                pass
            else:
                try:
                    d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                    if ver == "3.3":
                        d.set_version(3.3)
                    data = d.status()
                    if 'dps' in data:     
                        item['devId']= data    
                        #state = alertdim + "Off" + dim
                        try:
                            if '20' in data['dps'] or '20' in data['devId']:     # if '1' to '20' for all Devices
                                #state = "On" 
                                #print("    %s[%s] - %s%s - %s - DPS: %r" %
                                #    (name, ip, state, data['dps']))
                                print("\nEACH TREATLIFE SWITCH TO NODE WITH ADDNODE FROM HERE!!!") ########################## addNode HERE!! ######################################################################
                                print("%-35.35s %-24s %-16s %-17s %-5s" % (
                                    item["name"],
                                    item["id"],
                                    item["ip"],
                                    item["key"],
                                    item["ver"]))
                            else:
                             pass
                        except:
                            pass
                    else:
                        pass
                except:
                    pass
                    
            polling.append(item)
        # for loop
    
###################################################### JSON STATUS ###################################################
        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}  #current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4) #output = json.dumps(current, indent=4)
        print("")
        ##print("Hello Here's the JSON \n " + output) #Prints output.json 
        print("")
        #print("Full json below", json_data)
####################################################################################### NODE SWITCH CLASS START HERE  ##########################################################################################################
#class SwitchNodes(polyinterface.Node):
    #def __init__(self, controller, primary, address, name): #, ip, id1, key1
    #    super(SwitchNodes, self).__init__(controller, primary, address, name)

######################## SEPERATE OUT THE SWITCHES THEY HAVE "devId" IN BETWEEN 'DPS' or should I use length???? ############## 

######################## Passed to Nodes #############################        
       
        print("Currently Passed Name:", item["name"])
        DEVICEID = item["id"] #"017743508caab5f0973e"
        print("Currently Passed ID:", DEVICEID)  
        DEVICEIP = item["ip"] #"192.168.1.146"
        print("Currently Passed IP:",DEVICEIP)  
        DEVICEKEY = item["key"] #"e779c96c964f71b2"
        print("Currently Passed KEY:",DEVICEKEY + "\n")  
        DEVICEVERS = "us"

########################################################################################### NODE SERVER NODES #################################################################################################################
######################## Node Switch by DEVICE Example #########################################
        
        # Check for environmental variables and always use those if available
        DEVICEID = os.getenv("DEVICEID", DEVICEID)
        DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
        DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
        DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

        if data["dps"] != '20':
            #print("\nTreatLife - Smart Device Test [%s]\n" % tinytuya.__version__)
            print("TESTING NODE Switch by DEVICE: ", item["name"], '%s at %s with key %s version %s' %
                  ( DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

        # Connect to the device - replace with real values
        d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
        d.set_version(3.3)
        
        # Payload to Cycle Switch
        payload1=d.generate_payload(tinytuya.CONTROL, {'1': False, '9': 0})
        payload2=d.generate_payload(tinytuya.CONTROL, {'1': True, '9': 0})

        # Send the payload to the device
        # Test by DEVICE
        
        if data["devId"] != '20':
            print("\nTest Cycle Switch by DEVICE ON")
            d._send_receive(payload1)
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)
            time.sleep(2)
            print("\n\nTest Cycle Switch by DEVICE OFF")
            d._send_receive(payload2)
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)

  ###################### Node Light by DEVICE Example #########################################
        
        # Check for environmental variables and always use those if available
        DEVICEID = os.getenv("DEVICEID", DEVICEID)
        DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
        DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
        DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)
        
        if data["dps"] == '20':
            #print("\nTreatLife - Smart Light Test [%s]\n" % tinytuya.__version__)
            print('\n\nTESTING NODE Light by DEVICE: Device ', item["name"], '%s at %s with key %s version %s' %
                  (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

        # Connect to the device - replace with real values
        d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
        d.set_version(3.3)
        
        # Payload to Cycle Light
        payload1=d.generate_payload(tinytuya.CONTROL, {'20': False, '2': 50})
        payload2=d.generate_payload(tinytuya.CONTROL, {'20': True, '2': 50})

        if data["dps"] == '20': #if data["dps"] or item["dps"] != '1': TRY WHEN BACK
            print("\nTest Cycle Light by DEVICE ON")
            d._send_receive(payload1)
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            print("\n\nTest Cycle Light by DEVICE OFF\n")
            d._send_receive(payload2)
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)    
    
  ###################### Node Switch by NAME Example #########################################  
        
        # Turn on a device by name
        def turn_on(name):
            # find the right item that matches name
            for data['devId'] in item['devId']:      ## 'devId' works: dps does not: devices 
                if item["name"] == name:
                    break
            print("\nTurning On: %s" % item["name"])
            d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
            d.set_version(float(item["ver"]))
            d.set_status(True)
       
             # Turn off a device by name
        def turn_off(name):
            # find the right item that matches name
            for data['devId'] in item['devId']:
                if item["name"] == name:
                    break
            print("\nTurning Off: %s" % item["name"])
            d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
            d.set_version(float(item["ver"]))
            d.set_status(False)
       
        if data["dps"] != '20':
            print("\n\nTest Cycle Switch by Name \n")
            turn_off('Switch Family Room Sconces') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)
            time.sleep(2)
            turn_on('Switch Family Room Sconces') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)
            time.sleep(2)
            turn_off('Switch Office Outside Lights') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)
            time.sleep(2)
            turn_on('Switch Office Outside Lights') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Switch: %r' % data)

  ###################### Node Light by NAME Example #########################################
   
        # Turn on a device by name
        def turn_on(name):
            if data["dps"] == '20':
                # find the right item that matches name
                for data['dps'] in item['dps']:
                    if item["name"] == name:
                        break
                print("\nTurning On: %s" % item["name"])
                d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
                d.set_version(float(item["ver"]))
                d.set_status(True)

             # Turn off a device by name
        def turn_off(name):
            if data["dps"] == '20':
                # find the right item that matches name
                for data['dps'] in item['dps']:
                    if item["name"] == name:
                        break
                print("\nTurning Off: %s" % item["name"])
                d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
                d.set_version(float(item["ver"]))
                d.set_status(False)
        
        if data["dps"] == '20':
            print("\n\nTest Cycle Light by Name \n")
            turn_off('Office Light') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            turn_on('Office Light') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            turn_off('Garage') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            turn_on('Garage') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            turn_off('Under Cabinets') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            turn_on('Under Cabinets') #Switch Family Room Sconces #Switch Office Outside Lights
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
        
        # Who was passed
        print("\n" + item["name"])
        print(item["id"])
        print(item["ip"])
        print(item["key"] + "\n")


    
    print("\nDone.\n")
    return

if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass
