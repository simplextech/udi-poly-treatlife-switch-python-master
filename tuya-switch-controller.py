#!/usr/bin/env python
"""
This is a NodeServer template for Polyglot v2 written in Python2/3
by Einstein.42 (James Milne) milne.james@gmail.com
"""
try:
    import polyinterface
    from polyinterface import Controller,LOG_HANDLER,LOGGER
except ImportError:
    import pgc_interface as polyinterface
import sys
import time
import os
import requests
import hmac
import hashlib
import json
import pprint
import logging
import tinytuya 
#from tinttuya import tuyaPlatform


LOGGER = polyinterface.LOGGER
# IF you want a different log format than the current default
LOG_HANDLER.set_log_format('%(asctime)s %(threadName)-10s %(name)-18s %(levelname)-8s %(module)s:%(funcName)s: %(message)s')
"""
polyinterface has a LOGGER that is created by default and logs to:
logs/debug.log
You can use LOGGER.info, LOGGER.warning, LOGGER.debug, LOGGER.error levels as needed.
"""
class Controller(polyinterface.Controller):
    def __init__(self, polyglot):
        super(Controller, self).__init__(polyglot)
        self.name = 'Tuya-Switch'
        self.poly.onConfig(self.process_config)
        self.ip = None
        self.uri = None
        self.item = None

    def start(self):
        # This grabs the server.json data and checks profile_version is up to date
        serverdata = self.poly.get_server_data()
        LOGGER.info('Started Tuya-Switch NodeServer {}'.format(serverdata['version']))
        self.check_params()
        #self.tuyaPlatform(self, self.uri, 'apiKey', 'apiSecret', 'Controller') #, 'uri', 'apiKey', 'apiSecret'
        self.poly.add_custom_config_docs("<b>And this is some custom config data</b>")

    #class tuyaPlatform:
    #    def __init__(REGION, KEY, SECRET, uri):
    #        self.tuyaPlatform = Device()

    def shortPoll(self):
        self.discover()

    def longPoll(self):
        self.discover()

    def query(self,command=None):
        self.check_params()
        for node in self.nodes:
            self.nodes[node].reportDrivers()

    def tuyaPlatform(self, apiRegion, apiKey, apiSecret, uri, token=None):
        request = "https://openapi.tuya%s.com/v1.0/%s" % (apiRegion,uri)
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
        response = requests.get(request, headers=headers)
        try:
            response_dict = json.loads(response.content.decode())
        except:
            try:
                response_dict = json.loads(response.content)
            except:
                LOGGER.debug("Failed to get valid JSON response")

        #return(response_dict)

    

    def wizard(self, command, color=True):
        config = {}
        config['apiKey'] = 'default_apiKey'  #'txejpdfda9iwmn5cg2es'
        config['apiSecret'] = 'default_apiSecret'   #'46d6072ffd724e0ba5ebeb5cc6b9dce9'
        config['apiRegion'] = 'us'
        config['apiDeviceID'] = 'default_apiDeviceId'  #'017743508caab5f0973e'
        needconfigs = True

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
        REGION = config['apiRegion'] # us, eu, cn, in
        LANG = 'en' # en or zh

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

        #Display device list
        LOGGER.info("\n\n"  + "Device Listing\n" )
        output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
        LOGGER.info(output)

        # Save list to devices.json
        ##LOGGER.info(bold + "\n>> " + normal + "Saving list to " + DEVICEFILE)
        ##with open(DEVICEFILE, "w") as outfile:
        ##    outfile.write(output)
        ##LOGGER.info(dim + "    %d registered devices saved" % len(tuyadevices))
        
        if('Y'[0:1].lower() != 'n'):
            # Scan network for devices and provide polling data
            ##LOGGER.info(normal + "\nScanning local network for Tuya devices...")
            devices = tinytuya.deviceScan(False, 20)
            ##LOGGER.info("    %s%s local devices discovered%s" %
            ##      (len(devices)))
            ##LOGGER.info("")

            def getIP(d, gwid):
                for ip in d:
                    if (gwid == d[ip]['gwId']):
                        return (ip, d[ip]['version'])
                return (0, 0)

            polling = []
        LOGGER.info("Polling local devices...")
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
                LOGGER.info("    %s[%s] - %s%s - %sError: No IP found%s" %
                      (name, ip, name))
            else:
                try:
                    d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                    if ver == "3.3":
                        d.set_version(3.3)
                    data = d.status()
                    if 'dps' in data:
                        item['devId'] = data
                        #state = alertdim + "Off" 
                        try:
                            if '1' in data['dps'] or '1' in data['devId']:
                                #state = "On" 
                                #LOGGER.info("    %s[%s] - %s%s - %s - DPS: %r" %
                                #    (name, ip, state, data['dps'])
                                LOGGER.info("\nEACH TREATLIFE SWITCH TO NODE WITH ADDNODE FROM HERE!!!")
                                LOGGER.info("%-35.35s %-24s %-16s %-17s %-5s" % (
                                    item["name"],
                                    item["id"],
                                    item["ip"],
                                    item["key"],
                                    item["ver"]))
                            else:
                                #LOGGER.info("    %s[%s] - %s%s - DPS: %r" %
                                #    (name, ip, data['dps']))
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
                    pass
                    #print("    %s[%s] - %s%s - %sNo Response" %
                    #      (subbold, name, dim, ip, alertdim))
            polling.append(item)
        # for loop

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4) 
        SWITCHID = i['id']
        SWITCHIP = item["ip"] 
        SWITCHKEY = item["key"] 
        LOGGER.info("Currently Passed Name:", 'item'["name"])
        LOGGER.info('SWITCHID') # Device Name
        #LOGGER.info(SWITCHIP) # Device IP
        #LOGGER.info(SWITCHKEY)
        LOGGER.info("TEST1 ID" + 'item'["id"]) # Device ID
        LOGGER.info("TEST1 KEY" + 'item'["key"]) # Device Key
        self.addNode(SwitchNodes1(self, self.address, 'tuyaswitch1', 'TreatLife-1', SWITCHID))       


    def discover(self,*args, **kwargs):    
        #if "id" is not None:
        #    self.addNode(SwitchNodes1(self, self.address, 'tuyaswitch1', 'TreatLife-1', 'SWITCHID'))
        if "id" is not None: 
            self.addNode(SwitchNodes2(self, self.address, 'tuyaswitch2', 'TreatLife-2'))
        
    def delete(self):
        LOGGER.info('Removing Tuya Switch.')

    def stop(self):
        LOGGER.debug('NodeServer stopped.')

    def process_config(self, config):
        # this seems to get called twice for every change, why?
        # What does config represent?
        LOGGER.info("process_config: Enter config={}".format(config));
        LOGGER.info("process_config: Exit");

    def heartbeat(self,init=False):
        LOGGER.debug('heartbeat: init={}'.format(init))
        if init is not False:
            self.hb = init
        LOGGER.debug('heartbeat: hb={}'.format(self.hb))
        if self.hb == 0:
            self.reportCmd("DON",2)
            self.hb = 1
        else:
            self.reportCmd("DOF",2)
            self.hb = 0

    def set_module_logs(self,level):
        logging.getLogger('urllib3').setLevel(level)

    def set_debug_level(self,level):
        LOGGER.debug('set_debug_level: {}'.format(level))
        if level is None:
            level = 30
        level = int(level)
        if level == 0:
            level = 30
        LOGGER.info('set_debug_level: Set GV1 to {}'.format(level))
        self.setDriver('GV1', level)
        # 0=All 10=Debug are the same because 0 (NOTSET) doesn't show everything.
        if level <= 10:
            LOGGER.setLevel(logging.DEBUG)
        elif level == 20:
            LOGGER.setLevel(logging.INFO)
        elif level == 30:
            LOGGER.setLevel(logging.WARNING)
        elif level == 40:
            LOGGER.setLevel(logging.ERROR)
        elif level == 50:
            LOGGER.setLevel(logging.CRITICAL)
        else:
            LOGGER.debug("set_debug_level: Unknown level {}".format(level))
        # this is the best way to control logging for modules, so you can
        # still see warnings and errors
        #if level < 10:
        #    self.set_module_logs(logging.DEBUG)
        #else:
        #    # Just warnigns for the modules unless in module debug mode
        #    self.set_module_logs(logging.WARNING)
        # Or you can do this and you will never see mention of module logging
        if level < 10:
            LOG_HANDLER.set_basic_config(True,logging.DEBUG)
        else:
            # This is the polyinterface default
            LOG_HANDLER.set_basic_config(True,logging.WARNING)

    def check_params(self):
        """
        This is an example if using custom Params for user and password and an example with a Dictionary
        """
        self.removeNoticesAll()
        #self.addNotice('Hey there, my IP is {}'.format(self.poly.network_interface['addr']),'hello')
        #self.addNotice('Hello Friends! (without key)')
        default_apiKey = 'apiKey'
        default_apiSecret = 'apiSecert'
        default_apiDeviceId = 'apiDeviceId'
        default_apiRegion = "us"
        LANG = "en"



        if 'apiKey' in self.polyConfig['customParams']:
            self.key = self.polyConfig['customParams']['apiKey']
        else:
            self.key = default_apiKey
            LOGGER.error('check_params: apiKey is not defined in customParams, please add it.  Using {}'.format(self.key))
            st = False

        if 'apiSecert' in self.polyConfig['customParams']:
            self.secert = self.polyConfig['customParams']['apiSecert']
        else:
            self.secert = default_apiSecret
            LOGGER.error('check_params: apiSecert is not defined in customParams, please add it.  Using {}'.format(self.secert))
            st = False

        if 'apiDeviceId' in self.polyConfig['customParams']:
            self.devid = self.polyConfig['customParams']['apiDeviceId']
        else:
            self.devid = default_apiDeviceId
            LOGGER.error('check_params: apiDeviceId is not defined in customParams, please add it.  Using {}'.format(self.devid))
            st = False    
        
        
        # Make sure they are in the params
        #'some_example': '{ "type": "TheType", "host": "host_or_IP", "port": "port_number" }'
        self.addCustomParam({'apiDeviceId': self.devid, 'apiSecert': self.secert, 'apiKey': self.key, })

        # Add a notice if they need to change the user/password from the default.
        #if self.key == default_apiKey or self.secert == default_apiSecret or self.devid == default_apiDeviceId:
            # This doesn't pass a key to test the old way.
            #self.addNotice('Please set proper apiKey and apiSecert in configuration page, and restart this nodeserver')
        # This one passes a key to test the new way.
        #self.addNotice('This is a test','test')

    def remove_notice_test(self,command):
        LOGGER.info('remove_notice_test: notices={}'.format(self.poly.config['notices']))
        # Remove all existing notices
        self.removeNotice('test')

    def remove_notices_all(self,command):
        LOGGER.info('remove_notices_all: notices={}'.format(self.poly.config['notices']))
        # Remove all existing notices
        self.removeNoticesAll()

    def update_profile(self,command):
        LOGGER.info('update_profile:')
        st = self.poly.installprofile()
        return st

    def cmd_set_debug_mode(self,command):
        val = int(command.get('value'))
        LOGGER.debug("cmd_set_debug_mode: {}".format(val))
        self.set_debug_level(val)

    """
    Optional.
    Since the controller is the parent node in ISY, it will actual show up as a node.
    So it needs to know the drivers and what id it will use. The drivers are
    the defaults in the parent Class, so you don't need them unless you want to add to
    them. The ST and GV1 variables are for reporting status through Polyglot to ISY,
    DO NOT remove them. UOM 2 is boolean.
    The id must match the nodeDef id="controller"
    In the nodedefs.xml
    """
    id = 'controller'
    commands = {
        'QUERY': query,
        'DISCOVER': discover,
        'UPDATE_PROFILE': update_profile,
        'REMOVE_NOTICES_ALL': remove_notices_all,
        'REMOVE_NOTICE_TEST': remove_notice_test,
        'SET_DM': cmd_set_debug_mode,
               
        
    }
    drivers = [
        {'driver': 'ST', 'value': 1, 'uom': 2},
        {'driver': 'GV1', 'value': 10, 'uom': 25},
         
    ]

    

class SwitchNodes1(polyinterface.Node):
    def __init__(self, controller, primary, address, name, SWITCHID): #, ip, id1, key1 key, ip, id
        super(SwitchNodes1, self).__init__(controller, primary, address, name)
        self.SWITCHID = SWITCHID
        LOGGER.info(SWITCHID)
        #LOGGER.info("IP Address?" + 'IP')
    
    
    def start(self):
        #SWITCHIP = 'IP'
        #LOGGER.info('IP')
        #LOGGER.info(ip)
        #LOGGER.info('TESTING1: Switch %s' % (id))
        #LOGGER.info(id)
        
        DEVICEID = "017743508caab5f0973e"
        DEVICEIP = "192.168.1.146"
        DEVICEKEY = "e779c96c964f71b2"
        DEVICEVERS = "us"
        #LOGGER.info(DEVICEID)
        #LOGGER.info(DEVICEIP)
        #LOGGER.info(DEVICEKEY)
        #LOGGER.info('us')

        # Check for environmental variables and always use those if available
        DEVICEID = os.getenv("DEVICEID", DEVICEID)
        DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
        DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
        DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

        LOGGER.info("TreatLife - Smart Switch Test [%s]\n" % tinytuya.__version__)
        LOGGER.info('TESTING: Device %s at %s with key %s version %s' %
                    (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

        LOGGER.info('TESTING: Device %s' %
                    (DEVICEIP))

        d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
        d.set_version(3.3)

        # Generate the payload to send - add all the DPS values you want to change here
        #if data != [0]:
        payload1=d.generate_payload(tinytuya.CONTROL, {'1': False, '2': 50})
        #    time.sleep(2)
        payload2=d.generate_payload(tinytuya.CONTROL, {'1': True, '2': 50})
        #    time.sleep(2)

        d._send_receive(payload1)
        time.sleep(2)
        d._send_receive(payload2)
        time.sleep(2)
        d._send_receive(payload1)
        time.sleep(2)
        d._send_receive(payload2)

        data = d.status()
        LOGGER.info('\nCurrent Status of Switch: %r' % data) #%r
 
    def setSwOn(self, command):
        self.setDriver('GV2', 1)
        payload1 = None
        payload1=d.generate_payload(tinytuya.CONTROL, {'1': False, '2': 50})
        d=tinytuya.OutletDevice
        LOGGER.debug(("\nTest Cycle Switch by def on"))
        d._send_receive(payload1)
        

    def setSwOff(self, command):
        #payload2 = None
        #d._send_receive(payload2)
        self.setDriver('GV2', 0)      

    def query(self,command=None):
        self.reportDrivers()

    "Hints See: https://github.com/UniversalDevicesInc/hints"
    hint = [1,2,3,4]
    drivers = [{'driver': 'ST', 'value': 1, 'uom': 2},
              {'driver': 'GV2', 'value': 0, 'uom': 2},
                  
    ]
    
    id = 'tuyaswitch1'
    
    commands = {
                    'DON': setSwOn,
                    'DOF': setSwOff,
                    'QUERY': query,
    }
    

class SwitchNodes2(polyinterface.Node):
    def __init__(self, controller, primary, address, name): #, ip, id1, key1 key, ip, id
        super(SwitchNodes2, self).__init__(controller, primary, address, name)
        #self.ip = ip
        #self.id = id
        #self.key = key
        #self.data = data
        
        #LOGGER.info(ip)
    
    
    def start(self):
        
        #LOGGER.info('TESTING1: Switch %s' % (id))
        #LOGGER.info(id)
        
        DEVICEID = "017743508caab5f385a7"
        DEVICEIP = "192.168.1.147"
        DEVICEKEY = "7b8f2415ac96dfea"
        DEVICEVERS = "us"
        #LOGGER.info(DEVICEID)
        #LOGGER.info(DEVICEIP)
        #LOGGER.info(DEVICEKEY)
        #LOGGER.info('us')

        # Check for environmental variables and always use those if available
        DEVICEID = os.getenv("DEVICEID", DEVICEID)
        DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
        DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
        DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

        LOGGER.info("TreatLife - Smart Switch Test [%s]\n" % tinytuya.__version__)
        LOGGER.info('TESTING: Device %s at %s with key %s version %s' %
                    (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

        LOGGER.info('TESTING: Device %s' %
                    (DEVICEIP))

        d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
        d.set_version(3.3)
        
        # Generate the payload to send - add all the DPS values you want to change here
        #if data != [0]:
        payload1=d.generate_payload(tinytuya.CONTROL, {'1': False, '2': 50})
        #    time.sleep(2)
        payload2=d.generate_payload(tinytuya.CONTROL, {'1': True, '2': 50})
        #    time.sleep(2)
     
        d._send_receive(payload1)
        time.sleep(2)
        d._send_receive(payload2)
        time.sleep(2)
        d._send_receive(payload1)
        time.sleep(2)
        d._send_receive(payload2)
       
        data = d.status()
        LOGGER.info('\nCurrent Status of Switch: %r' % data) #%r
        
  
    def setSwOn(self, command):
        self.setDriver('GV2', 1)
        
    def setSwOff(self, command):
        self.setDriver('GV2', 0)      
    
    def query(self,command=None):
        self.reportDrivers()

    "Hints See: https://github.com/UniversalDevicesInc/hints"
    hint = [1,2,3,4]
    drivers = [{'driver': 'ST', 'value': 1, 'uom': 2},
              {'driver': 'GV2', 'value': 0, 'uom': 2},
                  
    ]
    
    id = 'tuyaswitch2'
    
    commands = {
                    'DON': setSwOn,
                    'DOF': setSwOff,
                    'QUERY': query,
    }
        

if __name__ == "__main__":
    try:
        polyglot = polyinterface.Interface('TuyaSwitch')
        polyglot.start()
        control = Controller(polyglot)
        control.runForever()
        ""
    except (KeyboardInterrupt, SystemExit):
        polyglot.stop()
        sys.exit(0)
        """
        Catch SIGTERM or Control-C and exit cleanly.
        """
