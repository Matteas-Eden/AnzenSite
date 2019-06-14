import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import sqlite3
import socket
from datetime import datetime, timedelta
from helperFuncs import generateSignature, encryptMessage
#import time

#Macros
root_url = "http://cs302.kiwi.land/api"
static_dir = "static/"
privateKey = ''
publicKey = ''
_username = "mede607"
_password = "Matteas-Eden_489439263"
_encoding = "utf-8"
_ip = "579addaa.ngrok.io"#socket.gethostbyname(socket.gethostname())
LOGIN_RECORD = ''
SERVER_TIME = 0
PORT = "10100"
#API key header
#?X-username=mede607?X-apikey=6y1yVCUBr3pp1jynvudO
USERS = {}

#View
def displaySplash():
    print(
    """
    ===========WELCOME===========
    Available commands:
    list : display API command list
    update : update API command list
    exit : exits the program
    <API_CMD> : execute an API command with a pre-defined payload
    """
    )

def getCommandFromUser():
    cmd = input(">> ").split()
    return cmd

#File I/O
def readKeys(): 
    global privateKey, publicKey
    try:
        with open(static_dir + "keys.txt",'r') as f:
            privateKey = bytes(f.readline().strip().split("::")[1],_encoding)
            publicKey = bytes(f.readline().strip().split("::")[1],_encoding)
    except:
        print("Error encountered with file read, keys not loaded")
    #else:
        #print(publicKey.decode(_encoding) + ", " + privateKey.decode(_encoding) +", " + str(signature))

def writeKeys(privateKey,publicKey):
    with open(static_dir + "keys.txt",'w') as f:
        f.write("privateKey" + "::" + privateKey.decode(_encoding) + '\n')
        f.write("publicKey" + "::" + publicKey.decode(_encoding) + '\n')

#Keys and signatures
def generateAndStoreKeys():
    #Generate private key
    private_key = nacl.signing.SigningKey.generate() #Private key
    private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder)
    #private_key_hex_str = private_key_hex.decode(_encoding)

    #Generate a public key from the private key
    pub_key = private_key.verify_key #Public key
    pub_key_hex = pub_key.encode(encoder=nacl.encoding.HexEncoder)
    #pub_key_hex_str = pub_key_hex.decode(_encoding)

    writeKeys(private_key_hex, pub_key_hex)

#API control
def callAPI(api_command,payload={"None":None}):

    url = root_url + '/' + str(api_command)

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (_username, _password))
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

def checkResponse(response,verbose):
    if (verbose):
        print("//////////// RESPONSE ////////////")
        print(json.dumps(response,indent=4))
        print("////////////// END ///////////////")
    #else:
        #print("Response is: " + response["response"])
    return (True if not response == None else False)

#API Commands
def listAPI(**args):
    #Read API commands from a file
    #print("[ListAPI] to be implemented")
    print("========API COMMANDS========")
    with open("static/api_cmd.txt") as f:
        for line in f:
            print(line.strip().replace('_',''))
    print("========END COMMANDS========")

def updateAPI(verbose):
    #Get and write API commands into a file
    #print("[UpdateAPI] to be implemented")
    try:
        response = callAPI('list_apis')
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        if checkResponse(response,verbose):
            with open("static/api_cmd.txt",'w') as f:
                #json.dump(response,f)
                for k in response:
                    f.write(k[1:] + '\n')

def ping(verbose):
    global SERVER_TIME
    print("Pinging server...")
    pingSignature = generateSignature(privateKey, publicKey.decode(_encoding))
    try:
        response = callAPI('ping',payload={
            "pubkey":publicKey.decode(_encoding),
            "signature":pingSignature
        })
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        if checkResponse(response,verbose):
            SERVER_TIME = response["server_time"]
            return True
    return False

def broadcast(verbose):
    #Broadcast a message
    msg = input("Message >> ")
    currentTime = getTime(verbose)
    #timestamp = SERVER_TIME
    #print(str(timestamp))
    broadcast_signature = generateSignature(privateKey, LOGIN_RECORD+msg+str(currentTime))
    #print(broadcast_signature)
    try:
        response = callAPI('rx_broadcast',payload={
            "loginserver_record":LOGIN_RECORD,
            "message":msg,
            "sender_created_at":str(currentTime),
            "signature":broadcast_signature
        })
    except urllib.error.HTTPError as err:
        #print(json.dumps(response,indent=4))
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)

def privateMessage(verbose):
    #Send a message to another client
    global USERS, LOGIN_RECORD

    user = input("Target User >> ")
    if not user in USERS:
        print("Requested user is not known. Run 'listusers' to update known user list.")
        return

    msg = input("Message >> ")
    msg = msg.replace("emoji",chr(128525))
    pubkey = USERS[user]

    currentTime = getTime(verbose)
    encrypted_msg = encryptMessage(msg,pubkey)
    signature = generateSignature(privateKey, LOGIN_RECORD + pubkey + user + encrypted_msg + str(currentTime))
    try:
        response = callAPI('rx_privatemessage?X-username=mede607?X-apikey=6y1yVCUBr3pp1jynvudO',payload={
            "loginserver_record":LOGIN_RECORD,
            "target_pubkey":pubkey,
            "target_username":user,
            "encrypted_message":encrypted_msg,
            "sender_created_at":str(currentTime),
            "signature":signature
        })
    except urllib.error.HTTPError as err:
        #print(json.dumps(response,indent=4))
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)

def report(verbose):
    status = input("Status >> ")
    try:
        response = callAPI('report',payload={
            "connection_location" : "2",
            "connection_address": _ip,# + ":" + PORT,
            "incoming_pubkey": publicKey.decode(_encoding),
            "status":status
        })
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)

def listUsers(**args):
    global USERS
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    try:
        response = callAPI('list_users')
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        if checkResponse(response,True):
            for user in response["users"]:
                #print(user)
                USERS[user["username"]] = user["incoming_pubkey"]
                try:
                    c.execute("""INSERT INTO Users(username, networkAddress, status, publicKey, lastSeenTime, lastLocation)
                            values(?,?,?,?,?,?)""",
                            [user["username"],user["connection_address"],user["status"],user["incoming_pubkey"],
                            user["connection_updated_at"],user["connection_location"]])
                except sqlite3.IntegrityError:
                    c.execute("""UPDATE Users
                    SET
                        networkAddress=?,
                        status=?, 
                        publicKey=?, 
                        lastSeenTime=?, 
                        lastLocation=?
                    WHERE username=?
                    """,
                    (user["connection_address"],user["status"],user["incoming_pubkey"],
                    user["connection_updated_at"],user["connection_location"],user["username"]))
    conn.commit()
    conn.close()
    return USERS

def addPubkey(verbose):
    try:
        response = callAPI('add_pubkey',payload={
            "username":_username,
            "pubkey":publicKey.decode(_encoding),
            "client_time":str(float('inf'))
        })
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)

def checkPubkey(verbose):
    global LOGIN_RECORD, SERVER_TIME
    try:
        response = callAPI('check_pubkey?pubkey=' + publicKey.decode(_encoding))
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)
        LOGIN_RECORD = response["loginserver_record"]
        SERVER_TIME = response["loginserver_record"].split(',')[2]

def getLoginServerPubkey(verbose):
    try:
        response = callAPI('loginserver_pubkey')
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,verbose)

def getLoginServerRecord(verbose):
    global LOGIN_RECORD, SERVER_TIME
    try:
        response = callAPI('get_loginserver_record',payload={
            "username":_username,
            "client_time":str(datetime.utcnow().timestamp()),
            "pubkey":publicKey.decode(_encoding)
        })
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        if checkResponse(response,verbose):
            LOGIN_RECORD = response["loginserver_record"]
            SERVER_TIME = response["loginserver_record"].split(',')[2]
            print("Current server time: " + str(SERVER_TIME))

def addPrivateData(**args):
    #print("Not yet implemented")
    global LOGIN_RECORD
    currentTime = getTime(verbose)
    privateData = {
        "prikeys":[privateKey.decode(_encoding)], #insecure
        "blocked_pubkeys":[],
        "blocked_usernames":[],
        "blocked_message_signatures":[],
        "blocked_words":[],
        "favourite_message_signatures":[],
        "friends_usernames":[]
    }

    print(json.dumps(privateData))

    signature = generateSignature(privateKey, json.dumps(privateData) + LOGIN_RECORD + str(currentTime))

    try:
        response = callAPI("add_privatedata",payload={
            "privatedata":json.dumps(privateData),
            "loginserver_record":LOGIN_RECORD,
            "client_saved_at":str(currentTime),
            "signature":signature
        })
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        if checkResponse(response,verbose):
            print("Private data updated")

def getPrivateData(**args):
    #print("Not yet implemented")
    #currentTime = getTime(verbose)
    #privateData = "YEET"
    #signature = generateSignature(privateData + LOGIN_RECORD + str(currentTime))
    try:
        response = callAPI("get_privatedata")
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        checkResponse(response,True)

def loadNewAPIKey(**args):
    response = callAPI("load_new_apikey")
    with open(static_dir + "apikey.txt",'w') as f:
        f.write(json.dumps(response))

    print(response)

def getTime(verbose):
    currentTime = datetime.now().timestamp()
    if verbose:
        print(currentTime)
    return currentTime

def printKeys(**args):
    print("Public Key: " + publicKey.decode(_encoding))
    print("Private Key: " + privateKey.decode(_encoding))
    #print("Signature: " + signature.decode(_encoding))

def spam(**args):
    while True:
        ping(False)

def getRecord(verbose):
    print(LOGIN_RECORD)

def getKnownUsers(**args):
    print(USERS)

def isServerOnline(**args):
    if ping(False):
        print("////////// Server is online //////////")
    else:
        print("////////// Server is offline //////////")


commands = {
    "list":listAPI,
    "listapis":listAPI,
    "update":updateAPI,
    "ping":ping,
    "report":report,
    "listusers":listUsers,
    #"addpubkey":addPubkey,
    "checkpubkey":checkPubkey,
    "rxbroadcast":broadcast,
    "rxprivatemessage":privateMessage,
    "loginserverpubkey":getLoginServerPubkey,
    "getloginserverrecord":getLoginServerRecord,
    "addprivatedata":addPrivateData,
    "getprivatedata":getPrivateData,
    #"genkeys":generateAndStoreKeys,
    #"readkeys":readKeys,
    #"showkeys":printKeys,
    "time":getTime,
    "spam":spam,
    "getRecord":getRecord,
    "getknownusers":getKnownUsers,
    "loadnewapikey":loadNewAPIKey,
    "exit":lambda **kwargs : exit()
}

if __name__ == "__main__":
    displaySplash()
    readKeys()
    getLoginServerRecord(False)
    isServerOnline()
    while (True):
        userIn = getCommandFromUser()
        command = userIn.pop(0)
        args = ''.join(s for s in userIn)
        verbose = 'v' in args
        if command not in commands:
            print("Command not recognised")
        else:
            commands[command](verbose=verbose)