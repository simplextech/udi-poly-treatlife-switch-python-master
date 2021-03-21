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
    print()

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
    #print("remote response",  response)
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
    print('Authentication' + ' [%s]' % (tinytuya.version))  
    
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
        #print()
        print("%-35.35s %-24s %-16s %-17s"  % (
            i['name'], 
            i['id'],
            i['ip'],
            i['local_key']
            ))

    # Display device list
    print("\n\n" + "Device Listing\n")
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    ##print("\n\n" + "Hello Here's are the Devices with INTERNET ACTIVE IP ADDRESSES \n\n " + output)  
    if('Y'[0:1].lower() != 'n'):
        # Scan network for devices and provide polling data
        ###print(normal + "\nScanning local network for Tuya devices...")
        devices = tinytuya.deviceScan(False, 1) #### changed 20 to 1
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
                            if '1' in data['dps'] or '20' in data['devId'] or '1' in data['dps']:       # if '20' in data['dps'] or '1' in data['devId'] or '20' in data['dps']: = all devices
                                #state = "On"                                                           # if '20' in data['dps'] or '20' in data['devId'] or '20' in data['dps']: = just lights
                                #print("    %s[%s] - %s%s - %s - DPS: %r" %                             # if '1' in data['dps'] or '20' in data['devId'] or '1' in data['dps']: = just switches
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
        print("Hello Here's the JSON \n " + output) #Prints output.json 
        print("")
        #print("Full json below", json_data)        
        
        for i in json_data['result']:
            item = {}
        item['name'] = i['name'].strip()
        
        print(i['name'])

    print("\nDone.\n")
    return

if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass





    

