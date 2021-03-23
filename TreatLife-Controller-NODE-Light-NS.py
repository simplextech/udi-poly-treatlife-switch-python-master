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
    print("API Key", apiKey)
    print("token ", payload)

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
    print('TreatLife Device Light Discovery')  
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

    # Use UID to get list of all Devices for User
    uri = 'users/%s/devices' % uid
    json_data = tuyaPlatform(REGION, KEY, SECRET, uri, token)
 
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
    #print("\n\n" + "Device Listing\n")
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    ##print("\n\n" + "Hello Here's are the Devices with INTERNET ACTIVE IP ADDRESSES \n\n " + output)  

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
        print("Polling TreatLife Light Devices...\n")  
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
                                print("\nEACH TREATLIFE LIGHT TO NODE WITH ADDNODE FROM HERE!!!") ########################## addNode HERE!! ######################################################################
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
        output = json.dumps(current, indent=4, ) #output = json.dumps(current, indent=4)
        print("")
        ##print("Hello Here's the JSON \n " + output) #Prints output.json 
        print("")
####################################################################################### NODE SWITCH CLASS START HERE  ##########################################################################################################
#class SwitchNodes(polyinterface.Node):
    #def __init__(self, controller, primary, address, name): #, ip, id1, key1
    #    super(SwitchNodes, self).__init__(controller, primary, address, name)

######################## SEPERATE OUT THE SWITCHES THEY HAVE "devId" IN BETWEEN 'DPS' or should I use length???? ############## 

######################## Passed to Nodes #############################        
       
        print("Currently Passed Name:", item["name"])
        DEVICENAME = item["name"]
        DEVICEID = item["id"] #"017743508caab5f0973e"
        print("Currently Passed ID:", DEVICEID)  
        DEVICEIP = item["ip"] #"192.168.1.146"
        print("Currently Passed IP:",DEVICEIP)  
        DEVICEKEY = item["key"] #"e779c96c964f71b2"
        print("Currently Passed KEY:",DEVICEKEY + "\n")  
        DEVICEVERS = "us"

########################################################################################### NODE SERVER NODES #################################################################################################################

  ###################### Node Light by DEVICE Example #########################################
        
        # Check for environmental variables and always use those if available
        DEVICENAME = os.getenv("DEVICEID", DEVICEID)
        DEVICEID = os.getenv("DEVICEID", DEVICEID)
        DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
        DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
        DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)
        
        if data["dps"] == '20':
            #print("\nTreatLife - Smart Light Test [%s]\n" % tinytuya.__version__)
            print('\n\nTESTING NODE Light by DEVICE: Device ', item["name"], '%s at %s with key %s version %s' %
                  (DEVICENAME, DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

        # Connect to the device - replace with real values
        d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
        d.set_version(3.3)
        
        # Payload to Cycle Light
        payload1=d.generate_payload(tinytuya.CONTROL, {'20': False, '2': 50})
        payload2=d.generate_payload(tinytuya.CONTROL, {'20': True, '2': 50})

        if data["dps"] != '1': #if data["dps"] or item["dps"] != '1': TRY WHEN BACK
            print("\nTest Cycle Light by DEVICE ON")
            d._send_receive(payload1)
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)
            time.sleep(2)
            print("\n\nTest Cycle Light by DEVICE OFF\n")
            d._send_receive(payload2)
            print('\nCurrent Status of', item["name"], 'Light: %r' % data)    
  
  ###################### Node Light by NAME Example #########################################
   
        # Turn on a device by name
        #def turn_on(name):
        #    if data["dps"] == '20':
                # find the right item that matches name
        #        for data['dps'] in item['dps']:
        #            if item["name"] == name:
        #                break
        
        print("\nTurning On: %s" % item["name"])
        d = tinytuya.BulbDevice(item["id"], item["ip"], item["key"])
        d.set_version(float(item["ver"]))
        d.set_socketPersistent(True)
        d.turn_off()
        # Show status of device
        #data = d.status()
        print('\nCurrent Status of Bulb: %r' % data)

             # Turn off a device by name
        #def turn_off(name):
        #    if data["dps"] == '20':
        #        # find the right item that matches name
        #        for data['dps'] in item['dps']:
        #            if item["name"] == name:
        #                break
        print("\nTurning Off: %s" % item["name"])
        d = tinytuya.BulbDevice(item["id"], item["ip"], item["key"])
        d.set_version(float(item["ver"]))
        d.set_socketPersistent(True)
        d.turn_on()

        # Dimmer Test
        print('\nDimmer Control Test')
        for level in range(11):
            print('    Level: %d%%' % (level*10))
            d.set_brightness_percentage(level*10)
            time.sleep(1)

        # Colortemp Test
        print('\nColortemp Control Test (Warm to Cool)')
        for level in range(11):
            print('    Level: %d%%' % (level*10))
            d.set_colourtemp_percentage(level*10)
            time.sleep(1)
        
        # Flip through colors of rainbow - set_colour(r, g, b):
        print('\nColor Test - Cycle through rainbow')
        rainbow = {"red": [255, 0, 0], "orange": [255, 127, 0], "yellow": [255, 200, 0],
                   "green": [0, 255, 0], "blue": [0, 0, 255], "indigo": [46, 43, 95],
                   "violet": [139, 0, 255]}
        for x in range(2):
            for i in rainbow:
                r = rainbow[i][0]
                g = rainbow[i][1]
                b = rainbow[i][2]
                print('    %s (%d,%d,%d)' % (i, r, g, b))
                d.set_colour(r, g, b)
                time.sleep(2)
            print('')

           # Turn off
        d.turn_off()
        time.sleep(1)

        # Random Color Test
        d.turn_on()
        print('\nRandom Color Test')
        for x in range(10):
            r = random.randint(0, 255)
            g = random.randint(0, 255)
            b = random.randint(0, 255)
            print('    RGB (%d,%d,%d)' % (r, g, b))
            d.set_colour(r, g, b)
            time.sleep(2)

        # Test Modes
        print('\nTesting Bulb Modes')
        print('    White')
        d.set_mode('white')
        time.sleep(2)
        print('    Colour')
        d.set_mode('colour')
        time.sleep(2)
        print('    Scene')
        d.set_mode('scene')
        time.sleep(2)
        print('    Music')
        d.set_mode('music')
        time.sleep(2)

        
        d.set_mode(b) #d.set_white()
        print('\nDimmer Control Test')
        for level in range(1):
            print('    Level: %d%%' % (level*1))

       # Dimmer Test
        print('\nDimmer Control Test')
        for level in range(5):
            print('    Level: %d%%' % (level*1))
            d.set_brightness_percentage(level*1)
            time.sleep(1)

        # Power Control Test
        #print('\nPower Control Test')
        #print('    Turn off lamp')
        #d.turn_off()
        #time.sleep(2)
        #print('    Turn on lamp')
        #d.turn_on()
        #time.sleep(2)
        # Done
        print('\nDone wWith Light Color Test')

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
