# TinyTuya Setup Wizard
# -*- coding: utf-8 -*-
"""
TinyTuya Setup Wizard Tuya based WiFi smart devices

Author: Jason A. Cox
For more information see https://github.com/jasonacox/tinytuya

Description
    Setup Wizard will prompt the user for Tuya IoT Developer credentials and will gather all 
    registered Device IDs and their Local KEYs.  It will save the credentials and the device
    data in the tinytuya.json and devices.json configuration files respectively. The Wizard 
    will then optionally scan the local devices for status.

    HOW to set up your Tuya IoT Developer account: iot.tuya.com:
    https://github.com/jasonacox/tinytuya#get-the-tuya-device-local-key

Credits
* Tuya API Documentation
    https://developer.tuya.com/en/docs/iot/open-api/api-list/api?id=K989ru6gtvspg
* TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    The TuyAPI/CLI wizard inspired and informed this python version.
"""
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
    """Tuya IoT Platform Data Access

    Parameters:
        * region     Tuya API Server Region: us, eu, cn, in
        * apiKey     Tuya Platform Developer ID
        * apiSecret  Tuya Platform Developer secret 
        * uri        Tuya Platform URI for this call
        * token      Tuya OAuth Token

    Playload Construction - Header Data:
        Parameter 	  Type    Required	Description
        client_id	  String     Yes	client_id
        signature     String     Yes	HMAC-SHA256 Signature (see below)
        sign_method	  String	 Yes	Message-Digest Algorithm of the signature: HMAC-SHA256.
        t	          Long	     Yes	13-bit standard timestamp (now in milliseconds).
        lang	      String	 No	    Language. It is zh by default in China and en in other areas.
        access_token  String     *      Required for service management calls

    Signature Details:
        * OAuth Token Request: signature = HMAC-SHA256(KEY + t, SECRET).toUpperCase()
        * Service Management: signature = HMAC-SHA256(KEY + access_token + t, SECRET).toUpperCase()

    URIs:
        * Get Token = https://openapi.tuyaus.com/v1.0/token?grant_type=1
        * Get UserID = https://openapi.tuyaus.com/v1.0/devices/{DeviceID}
        * Get Devices = https://openapi.tuyaus.com/v1.0/users/{UserID}/devices

    """
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

def wizard(color=True):
    # Get Configuration Data
    #CONFIGFILE = 'tinytuya.json'
    #DEVICEFILE = #'devices.json'
    SNAPSHOTFILE = 'output'
    config = {}
    config['apiKey'] = "txejpdfda9iwmn5cg2es"
    config['apiSecret'] = "46d6072ffd724e0ba5ebeb5cc6b9dce9"
    config['apiRegion'] = 'us'
    config['apiDeviceID'] = "017743508caab5f0973e"
    needconfigs = True
    ##try:
        # Load defaults
    ##    with open(CONFIGFILE) as f:
    ##        config = json.load(f)
   ## except:
        # First Time Setup
    ##    pass
    
    if(color == False):
        # Disable Terminal Color Formatting
        bold = subbold = normal = dim = alert = alertdim = ""
    else:
        # Terminal Color Formatting
        bold = "\033[0m\033[97m\033[1m"
        subbold = "\033[0m\033[32m"
        normal = "\033[97m\033[0m"
        dim = "\033[0m\033[97m\033[2m"
        alert = "\033[0m\033[91m\033[1m"
        alertdim = "\033[0m\033[91m\033[2m"

    print(bold + 'TinyTuya Setup Wizard' + dim + ' [%s]' % (tinytuya.version) + normal)
    print('')

    if(config['apiKey'] != '' and config['apiSecret'] != '' and
            config['apiRegion'] != '' and config['apiDeviceID'] != ''):
        needconfigs = False
        print("    " + subbold + "Existing settings:" + dim +
              "\n        API Key=%s \n        Secret=%s\n        DeviceID=%s\n        Region=%s" %
              (config['apiKey'], config['apiSecret'], config['apiDeviceID'],
               config['apiRegion']))
        print('')
        answer = 'Y' #input(subbold + '    Use existing credentials ' +
                  #     normal + '(Y/n): ')
        if('Y'[0:1].lower() == 'n'):
            needconfigs = True

    if(needconfigs):
        # Ask user for config settings
        print('')
        config['apiKey'] = input(subbold + "    Enter " + bold + "API Key" + subbold +
                                 " from tuya.com: " + normal)
        config['apiSecret'] = input(subbold + "    Enter " + bold + "API Secret" + subbold +
                                    " from tuya.com: " + normal)
        config['apiDeviceID'] = input(subbold +
                                      "    Enter " + bold + "any Device ID" + subbold +
                                      " currently registered in Tuya App (used to pull full list): " + normal)
        # TO DO - Determine apiRegion based on Device - for now, ask
        config['apiRegion'] = input(subbold + "    Enter " + bold + "Your Region" + subbold +
                                    " (Options: us, eu, cn or in): " + normal)
        # Write Config
        ##json_object = json.dumps(config, indent=4)
        ##with open(CONFIGFILE, "w") as outfile:
        ##    outfile.write(json_object)
        ##print(bold + "\n>> Configuration Data Saved to " + CONFIGFILE)
        ##print(dim + json_object)

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
        tuyadevices.append(item)

    # Display device list
    ##print("\n\n" + bold + "Device Listing\n" + dim)
    ##output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    ##print(output)

    # Save list to devices.json
    ##print(bold + "\n>> " + normal + "Saving list to " + DEVICEFILE)
    ##with open(DEVICEFILE, "w") as outfile:
    ##    outfile.write(output)
    ##print(dim + "    %d registered devices saved" % len(tuyadevices))

    # Find out if we should poll all devices
    #answer = 'Yes' #input(subbold + '\nPoll local devices? ' +
              #     normal + '(Y/n): ')
    if('Y'[0:1].lower() != 'n'):
        # Scan network for devices and provide polling data
        print(normal + "\nScanning local network for Tuya devices...")
        devices = tinytuya.deviceScan(False, 20)
        print("    %s%s local devices discovered%s" %
              (dim, len(devices), normal))
        print("")

        def getIP(d, gwid):
            for ip in d:
                if (gwid == d[ip]['gwId']):
                    return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("Polling local devices...")
        for i in tuyadevices:
            item = {}
            name = i['name']
            (ip, ver) = getIP(devices, i['id'])
            item['name'] = name
            item['ip'] = ip
            item['ver'] = ver
            item['id'] = i['id']
            item['key'] = i['key']
            if (ip == 0):
                print("    %s[%s] - %s%s - %sError: No IP found%s" %
                      (subbold, name, dim, ip, alert, normal))
            else:
                try:
                    d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                    if ver == "3.3":
                        d.set_version(3.3)
                    data = d.status()
                    if 'dps' in data:
                        item['devId'] = data
                        state = alertdim + "Off" + dim
                        try:
                            if '1' in data['devId'] or 'devId' in data['devId']:
                                state = bold + "On" + dim
                                print("    %s[%s] - %s%s - %s - DPS: %r" %
                                    (subbold, name, dim, ip, state, data['dps']))
                            else:
                                #print("    %s[%s] - %s%s - DPS: %r" %
                                #    (subbold, name, dim, ip, data['dps']))
                                pass
                        except:
                            #print("    %s[%s] - %s%s - %sNo Response" %
                            #      (subbold, name, dim, ip, alertdim))
                            pass
                    else:
                        #print("    %s[%s] - %s%s - %sNo Response" %
                        #      (subbold, name, dim, ip, alertdim))
                        pass
                except:
                    print("    %s[%s] - %s%s - %sNo Response" %
                          (subbold, name, dim, ip, alertdim))
            polling.append(item)
        # for loop

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4)
        #print(name)

        #print(bold + "\n>> " + normal + "Saving device snapshot data to " + SNAPSHOTFILE)
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)
          #  pass  
        #print(name)
        #print(ip)
        #print(id)
        #print(ver)
        #print(data)

######################### NOW INPUT SNAPSHOT FROM ABOVE INSTEAD OF PULLING FROM THE FILE $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
######################### So Far so Good creats json without writing it to an output file $$$$$$$$$$$$$$$$$$$$$$$$$$$$$ 
######################### Switch Poly will start here as a class $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
#Class switchNode(self, SNAPSHOT PASSED ############)      
        ######### PULLING FROM FILE ############
        with open(SNAPSHOTFILE) as json_file:   # 'snapshot.json'
        
            data = json.load(json_file)   # current gives error output
                                          # output 

######################## NEED TO BE ABLE TO SEPERATE OUT THE SWITCHES THEY HAVE "devId" IN BETWEEN 'DPS' $$$$$$$$$$$$$$$        
        # Print a table with all devices
        #print("%-25s %-24s %-16s %-17s %-5s" % ("Name","ID", "IP","Key","Version"))
        #for item in data['devices']:
        #    print("%-25.25s %-24s %-16s %-17s %-5s" % (
        #        item["name"],
        #        item["id"],
        #        item["ip"],
        #        item["key"],
        #        item["ver"]))
       
        # Print status of everything
        #for item in data["devices"]:
        #    print("\nDevice: %s" % item["name"])
        #    d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])  #adding devId instead of just id
        #    d.set_version(float(item["ver"]))
        #    status = d.status()  
        #    print(status)
        #    print(["devId"])  #Seems to print switch only

        # Turn on a device by name
        def turn_on(name):
            # find the right item that matches name
            for item in data["devices"]:
               if item["name"] == name:
                    break
            print("\nTurning On: %s" % item["name"])
            d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
            d.set_version(float(item["ver"]))
            d.set_status(True)

             # Turn off a device by name
        def turn_off(name):
            # find the right item that matches name
            for item in data["devices"]:
                if item["name"] == name:
                    break
            print("\nTurning Off: %s" % item["name"])
            d = tinytuya.OutletDevice(item["id"], item["ip"], item["key"])
            d.set_version(float(item["ver"]))
            d.set_status(False)

        # Test it
        turn_off('Office Outside Lights')
        time.sleep(1)
        turn_on('Office Outside Lights')

    
    
    
    print("\nDone.\n")
    return


if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass