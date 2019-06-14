import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import socket
from datetime import datetime, timedelta

USER = "mede607"
PASS = "Matteas-Eden_489439263"
PORT = 1337

def callAPI(ip_addr,api_command,payload={"None":None}):

    url = "http://" + ip_addr + ":" + str(PORT) + '/' + str(api_command)

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (USER, PASS))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload_str = json.dumps(payload)
    payload_str_bytes = bytes(payload_str,'utf-8')

    try:
        req = urllib.request.Request(url, data=payload_str_bytes, headers=headers)
        response = urllib.request.urlopen(req)
    except urllib.error.URLError as err:
        print("URL Error encountered: " + str(err))
        return

    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    JSON_object = json.loads(data.decode(encoding))
    # print(json.dumps(JSON_object,indent=4))
    return JSON_object

def ping_check(ip):
    response = callAPI(ip,'ping_check',payload={
        "my_time":str((datetime.now()).timestamp()),
        "my_active_usernames":"",
        "connection_address":"12.3.56.90:214",
        "connection_location":2
    })

if __name__=="__main__":
    #print("hello main")
    #ping_check("172.23.88.17")
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(ip)