### Original Beautiful Code by Jason Cox #
### Code Hacked by Steve Bailey for a Polyglot Node Server on Universal Devices ISY #############

####### Used to create controller and single node class for TreatLife product to polyinterface  #
# This adds api and secert to custom parameters then polls Switches  Most in test Node Server   #


# TinyTuya Switch Wizard
# -*- coding: utf-8 -*-
# Modules
import requests
import time
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

def tuyaPlatform(apiRegion, apiKey, apiSecret, uri, token=None):
    url = "https://openapi.tuya%s.com/v1.0/%s" % (apiRegion,uri)
    now = int(time.time()*1000)
    if(token==None):
        payload = apiKey + str(now)
    else:
        payload = apiKey + token + str(now)

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
    print(response_dict)

def wizard(color=True):
####################### This is already in Node Sever for Custom Parameters for api Information below ###########
# 
####################### Change All print statements to LOGGER.info() ############################################    
    # Get Configuration Data
    #CONFIGFILE = 'tinytuya.json'
    #DEVICEFILE = #'devices.json'
    #SNAPSHOTFILE = 'output.json'
    config = {}
    config['apiKey'] = "txejpdfda9iwmn5cg2es"
    config['apiSecret'] = "46d6072ffd724e0ba5ebeb5cc6b9dce9"
    config['apiRegion'] = 'us'
    config['apiDeviceID'] = "017743508caab5f0973e"
    needconfigs = True
####################################### Loads as custom parameters in Node Server ###############################
    ##try:
        # Load defaults
    ##    with open(CONFIGFILE) as f:
    ##        config = json.load(f)
   ## except:
        # First Time Setup
    ##    pass
    
    print('')
    print('Hello Polling Switches')
    print('') 
    print('TinyTuya Switch Discoverer' + ' [%s]' % (tinytuya.version)) #print(bold + 'TinyTuya Setup Wizard' + dim + ' [%s]' % (tinytuya.version) + normal)
    print('')

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
    #print("\n\n" + "Hello Here's are the Devices \n\n " + output)

    # Save list to devices.json
    ##print("\n>> " + "Saving list to " + DEVICEFILE)
    ##with open(DEVICEFILE, "w") as outfile:
    ##    outfile.write(output)
    ##    print("    %d registered devices saved" % len(tuyadevices))
    
######################### Device Switch Poller #################################
# 
# Using devId to poll Switches without lights or should i use key length??????#$$
#
# NEED TO GRAB SWITCH DEVICES AND MAKE THEM SEPARATE NODES FOR EACH SWITCH $$$$$$
#
######################### By-Pass Data Input ########################$$$$$$$$$$$$
    # Find out if we should poll all devices
    #answer = 'Yes' #input(subbold + '\nPoll local devices? ' +
              #     normal + '(Y/n): ')
    if('Y'[0:1].lower() != 'n'):
        # Scan network for devices and provide polling data
        ###print(normal + "\nScanning local network for Tuya devices...")
        devices = tinytuya.deviceScan(False, 20) #### changed 20 to 1
        #print("    %s%s local devices discovered%s" %
        #      ( len(devices)))
        #print("")

        def getIP(d, gwid):
            for ip in d:
                if (gwid == d[ip]['gwId']):
                    return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("\n" + "Polling Switch devices...\n")
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
                        item['devId'] = data
                        #state = alertdim + "Off" + dim
                        try:
                            if '1' in data['devId'] or 'devId' in data['devId']:
                                #state = "On" 
                                #print("    %s[%s] - %s%s - %s - DPS: %r" %
                                    #(name, ip, state, data['dps']))
                                print("%-35.35s %-24s %-16s %-17s %-5s" % (
                                    item["name"],
                                    item["id"],
                                    item["ip"],
                                    item["key"],
                                    item["ver"]))
                            else:
                                print("    %s[%s] - %s%s - DPS: %r" %
                                    (name, ip, data['devId']))
                                pass
                        except:
                            pass
                    else:
                        pass
                except:
                    pass
                    #print("    %s[%s] - %s%s - %sNo Response" %
                    #      (name, ip, alertdim))
            polling.append(item)
        # for loop
###################################################### Need to Clean this up ###################################################
        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}  #current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4) #output = json.dumps(current, indent=4)
        print("")
        print("Hello Here's the JSON \n " + output) #Prints output.json
        print("")

###################################################### NODE SWITCH CLASS START HERE  #########################################

#class SwitchNodes(polyinterface.Node):
    #def __init__(self, controller, primary, address, name): #, ip, id1, key1
    #    super(SwitchNodes, self).__init__(controller, primary, address, name)

######################## SEPERATE OUT THE SWITCHES THEY HAVE "devId" IN BETWEEN 'DPS' or should I use length???? ############## 
        ######################### OUTUT TEST RESULTS ###########################
        print("\n" + "Switch Passed Parameters")
        #print(name) ## Switch Office Outside Lights
        #print(ip)
        #print(item["id"])
        #print(item["key"])
        #print(data, item["name"])    ##print(data, item["name"]) ={ 'dps': {'20': True, '21': 'white', '22': 29, '23': 1000, '24': '00ad02a10318', '25': '000e0d0000000000000000c803e8', '26': 0}} Office Light
        #print(data['dps'], item["name"])   ##print(data['devices'], item["name"]) = {'20': True, '21': 'white', '22': 29, '23': 1000, '24': '00ad02a10318', '25': '000e0d0000000000000000c803e8', '26': 0} Office Light

        print("WHAT WE NEED TO PASS TO SWITCH CLASSES")
        print(name, ip, item["key"], item["id"])  ##print(name, ip, item["key"], item["id"]) = Office Light 192.168.1.147 805217605357161b ebfc16d57ed374932cjqfk NOW TO MAKE THIS A SWITCH
        print("devId FULL PAYLOAD RAW")
        print(item["devId"]) ##print(item["devId"]) = {'devId': '017743508caab5f0973e', 'dps': {'1': True, '9': 0}}
        print("\n" + "BOTH SWITCHES NOT PASSED?")
     ############## Function to start sort ################
        print("\n" + "Switch Status\n")
        if '1' in data['devId'] or 'devId' in data['devId']:
            print(
                item["name"],
                item["id"],
                item["ip"],
                item["key"]
                )

      
        print("\n" + "Data Status \n")
        print("Our Data" + "\n " + item["name"], data)  ## print("Our Data \n ",  item["name"], data) = ##print("Our Data \n ", data) = {'devId': '017743508caab5f0973e', 'dps': {'1': True, '9': 0}}
        print("")
        print("\nOur Devices" + "\n ", devices)
       
    

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
        
        # Test it
        turn_off('Switch Family Room Sconces') #Switch Family Room Sconces #Switch Office Outside Lights
        time.sleep(2)
        turn_on('Switch Family Room Sconces') #Switch Family Room Sconces #Switch Office Outside Lights
        time.sleep(2)
        turn_off('Switch Office Outside Lights') #Switch Family Room Sconces #Switch Office Outside Lights
        time.sleep(2)
        turn_on('Switch Office Outside Lights') #Switch Family Room Sconces #Switch Office Outside Lights
    
    print("\nDone.\n")
    return

if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass
