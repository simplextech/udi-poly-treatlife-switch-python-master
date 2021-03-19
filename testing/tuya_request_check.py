import requests
import time

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
                print("Failed to get valid JSON response")

        return(response_dict)
        print(response)