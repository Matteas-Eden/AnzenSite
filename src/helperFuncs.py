import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.utils
import nacl.secret
import nacl.pwhash.argon2i
import binascii
import sqlite3
from datetime import datetime

STR_ENCODING = 'utf-8'
HEADER_ENCODING = 'ascii'
LOGIN_SERVER_URL = "http://cs302.kiwi.land/api"

def createBasicHTTPHeader(username, password,**kwargs):
    """
    The point of this function is in the name, as it creates an HTTP header using
    BASIC authorisation.
    ///// INPUT /////
    username : String
    password : String
    ///// OUTPUT /////
    header : JSON
    """
    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode(HEADER_ENCODING))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode(HEADER_ENCODING),
        'Content-Type' : 'application/json; charset=utf-8'
    }
    return headers

def createAPIKeyHTTPHeader(username, api_key,**kwargs):
    """
    Creates an HTTP header using
    a provided API key for authorisation with the central login server
    ///// INPUT /////
    username : String
    api_key : String
    ///// OUTPUT /////
    header : JSON
    """
    #create HTTP API Key authorization header
    headers = {
        "X-username":username,
        "X-apikey":api_key,
        'Content-Type' : 'application/json; charset='+STR_ENCODING
    }
    return headers

def createSecretBox(password):
    """
    This function creates a secret box using a given password for symmetric encryption

    Keyword Arguments:
    password -- Password to be salted and used as key for the secret box

    Returns:
    secret_box -- Secret box
    """
    key_password_multi = str(password)*16
    password_byte = bytes(str(password), encoding=STR_ENCODING)

    salt = bytes(key_password_multi.encode(STR_ENCODING)[:16])
    ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
    # saltBytes = nacl.pwhash.argon2i.SALTBYTES

    secret_box_key = nacl.pwhash.argon2i.kdf(32,password_byte,salt,ops,mem)
    secret_box = nacl.secret.SecretBox(secret_box_key)
    return secret_box

def generatePrivateData(password,userPrefs):
    """
    Generate private data to be stored on the login server

    Keyword Arguments:
    password -- The password used to encrypt the private data
    privateKey -- A list of private keys to stored
    blocked_pubkeys -- A list of blocked pubkeys
    blocked_usernames -- A list of blocked usernames
    blocked_words -- A list of blocked words
    blocked_message_signatures -- A list of blocked message signatures
    favourite_message_signatures -- A list of message signatures
    friends_usernames -- A list of user's friends

    Returns:
    private_data -- An encrypted JSON object
    """

    secret_box = createSecretBox(password)

    private_data_bytes = bytes(json.dumps(userPrefs), encoding=STR_ENCODING)

    encrypted = secret_box.encrypt(private_data_bytes, encoder=nacl.encoding.Base64Encoder)
    private_data = encrypted.decode(STR_ENCODING)

    return private_data

def decryptPrivateData(encryptedPrivateData,password):

    secret_box = createSecretBox(password)

    plaintext = secret_box.decrypt(encryptedPrivateData,encoder = nacl.encoding.Base64Encoder)

    private_data = json.loads(plaintext.decode('utf-8'))
    print(json.dumps(private_data,indent=4))
    return private_data

def invokeAPI(root_url,api_command,headers,payload={}):
    """
    Invoke an API call on a given url by sending a payload with appropriate headers.

    Keyword arguments:
    root_url -- The url to invoke the API call on
    api_command -- The API command to invoke
    headers -- The headers to send with the request
    payload -- The payload to send (defaults to empty) (JSON)

    Returns:
    JSON
    """

    url = root_url + '/' + str(api_command)

    payload_str = json.dumps(payload)
    payload_str_bytes = bytes(payload_str,STR_ENCODING)

    try:
        req = urllib.request.Request(url, data=payload_str_bytes, headers=headers)
        response = urllib.request.urlopen(req,timeout=5)
    except urllib.error.URLError as err:
        print("API called: " + api_command)
        print("Error encountered: " + str(err))
        try:
            error_response = json.loads(err.read().decode(STR_ENCODING))
            print("Error message: " + error_response["message"])
        except:
            pass
        return None
    except:
        print("API called: ", api_command)
        print("Request to server timed out")
        return None

    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset(STR_ENCODING) #load encoding if possible (default to utf-8)
    response.close()

    server_response = json.loads(data.decode(encoding))
    if not api_command == "list_users":
        print(json.dumps(server_response,indent=4))
    return server_response

def checkDataMatchesFormat(data,fields):
    """
    Checks if a set of JSON data contains all of a given set of fields.

    The function checks that the fields listed in 'fields' are all
    present in the dictionary 'data'.

    Keyword Arguments:
    data -- The JSON to be checked
    fields -- A list of fields to check

    Returns:
    boolean literal
    """
    for field in fields:
        if field not in data.keys():
            return False
    
    return True

def addBroadcastToDB(broadcastMessage):
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    try:
        c.execute("""
        INSERT INTO Broadcasts(username,publicKey,message,timestamp,signature) values(?,?,?,?,?)"""
        ,(broadcastMessage["username"],broadcastMessage["publicKey"],broadcastMessage["message"],
        broadcastMessage["timestamp"],broadcastMessage["signature"]))
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()

def addMessageToDB(message):
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    try:
        c.execute("""
        INSERT INTO Messages(sendingUser,receivingUser,message,timestamp,signature) values(?,?,?,?,?)"""
        ,(message["sendingUser"],message["receivingUser"],message["message"],
        message["timestamp"],message["signature"]))
    except sqlite3.IntegrityError:
        print("Integrity Error")
        pass
    except:
        print("Other Error occurred")

    conn.commit()
    conn.close()

def encryptMessage(message,key):
    """
    Encrypts a message with a given key

    The message is encoded using UTF-8 into bytes and encrypted using a
    PyNaCl SealedBox created from the given key.

    Keyword Arguments:
    message -- The plaintext to encrypt
    key -- The key used to encrypt

    Returns:
    encrypted_msg_str -- The ciphertext
    """

    message_bytes = bytes(message,encoding=STR_ENCODING)
    key_bytes = bytes(key,encoding=STR_ENCODING)

    verifykey = nacl.signing.VerifyKey(key_bytes,encoder=nacl.encoding.HexEncoder)
    msg_publickey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(msg_publickey)

    encrypted = sealed_box.encrypt(message_bytes,encoder=nacl.encoding.HexEncoder)
    ecnrypted_msg_str = encrypted.decode(STR_ENCODING)

    return ecnrypted_msg_str

def decryptMessage(encrypted_message,key):
    """
    Decrypts ciphertext using a given key.

    Keyword arguments:
    encrypted_message -- Ciphertext, the message to be decrypted
    key -- the key being used to decrypt the message

    Returns:
    decrypted_message -- Plain text
    """
    en_message_bytes = bytes(encrypted_message,encoding=STR_ENCODING)
    key_bytes = bytes(key,encoding=STR_ENCODING)

    signingkey = nacl.signing.SigningKey(key_bytes,encoder=nacl.encoding.HexEncoder)
    priv_key = signingkey.to_curve25519_private_key()

    unseal_box = nacl.public.SealedBox(priv_key)
    decrypted_message = (unseal_box.decrypt(en_message_bytes,encoder=nacl.encoding.HexEncoder)).decode(STR_ENCODING)

    return decrypted_message

def generateSignature(key,signStr):
    """
    The purpose of this function is to generate a signature using the methods
    provided by PyNaCl.
    
    Keyword Arguments:
    key -- The key used to create the signature
    signStr -- The string to be signed
    
    Returns:
    signature_hex_str -- The signature as a string
    """
    #Generate a message to encrypt to then use a signature
    msg_bytes = bytes(signStr, encoding=STR_ENCODING)

    #Generate a signature
    signing_key = nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)
    signature_hex = signing_key.sign(msg_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signature_hex.signature.decode(STR_ENCODING)

    return signature_hex_str

def verifySignature(signature,message,pubkey):
    """
    Verifies a signature based on given parameters using a given key

    Keyword arguments:
    signature -- hex-encoded string
    message -- The plaintext message to compare against
    pubkey -- the public key of who created the signature as a hex-encoded string
    
    Returns:
    boolean literal i.e. True/False
    """

    sig_bytes = binascii.unhexlify(signature)
    msg_bytes = bytes(message,STR_ENCODING)

    verifykey = nacl.signing.VerifyKey(pubkey,encoder=nacl.encoding.HexEncoder)

    verified_msg = verifykey.verify(msg_bytes,sig_bytes).decode(STR_ENCODING)

    return message == verified_msg

def SelectQueryToSingleList(queryResult):
    listResult = []
    for x in queryResult:
        listResult.append(x[0])
    return listResult

def createKeysForUser():

    # Private key generation and encoding
    privatekey = nacl.signing.SigningKey.generate()
    privatekey_hexbytes = privatekey.encode(encoder=nacl.encoding.HexEncoder)
    privatekey_str = privatekey_hexbytes.decode(STR_ENCODING)

    # Public key generation and encoding
    publickey = privatekey.verify_key
    publickey_hexbytes = publickey.encode(encoder=nacl.encoding.HexEncoder)
    publickey_str = publickey_hexbytes.decode(STR_ENCODING)

    keys={
        "privkey":privatekey_str,
        "pubkey":publickey_str
    }

    return keys

def getBroadcastsFromDBForHTML():

    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    c.execute("SELECT username, message, timestamp, signature FROM Broadcasts ORDER BY timestamp DESC")
    rows = c.fetchall()
    broadcasts = []
    for record in rows:
        time_since = getTimeDiff(record[2])
        time_str = createTimeString(time_since,"day","")
        time_formatted = formatTimeString(time_str)
        msg = {
            "user":record[0],
            "message":record[1],
            "time":time_formatted,
            "signature":record[3]
        }
        broadcasts.append(msg)

    conn.commit()
    conn.close()
    return broadcasts

def getMessagesFromDBForHTML(user):

    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    c.execute("""
    SELECT sendingUser, receivingUser, message, timestamp, signature 
    FROM Messages
    WHERE receivingUser=? OR sendingUser=?
    ORDER BY timestamp DESC
    """,(user,user,))
    rows = c.fetchall()
    messages = []
    for record in rows:
        time_since = getTimeDiff(record[3])
        time_str = createTimeString(time_since,"day","")
        time_formatted = formatTimeString(time_str)
        msg = {
            "sender":record[0],
            "receiver":record[1],
            "message":record[2],
            "time":time_formatted,
            "signature":record[4]
        }
        messages.append(msg)

    conn.commit()
    conn.close()
    return messages

def getUsersFromDBForHTML():

    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    c.execute("SELECT username, status FROM Users WHERE status='online' or status='away'")
    rows = c.fetchall()
    userList = []
    for record in rows:
        user = {
            "name":record[0],
            "status":record[1]
        }
        userList.append(user)

    conn.commit()
    conn.close()
    return userList

def getTimeDiff(utcTimestamp):
    time_since = datetime.utcnow() - datetime.utcfromtimestamp(utcTimestamp)
    diff_days = time_since.days
    diff_hours = time_since.seconds // 3600
    diff_minutes = (time_since.seconds % 3600) // 60

    time_diff = {
        "day":diff_days,
        "hour":diff_hours,
        "minute":diff_minutes
    }

    return time_diff

def createTimeString(timeDict,field,timeStr):

    print("Formatting ", field)

    if field == "day":
        timeStr = createTimeString(timeDict,"hour",timeStr)
    elif field == "hour":
        timeStr = createTimeString(timeDict,"minute",timeStr)

    if timeDict[field] > 1:
        timeStr += "{} {}s ".format(timeDict[field],field)
    elif timeDict[field] == 1:
        timeStr += "{} {} ".format(timeDict[field],field)

    return timeStr

def formatTimeString(timeStr):
    strTokens = timeStr.split()
    #print(strTokens)
    #Even indices are numbers, odd indices are words
    nums = strTokens[0::2]
    words = strTokens[1::2]
    #print(nums)
    #print(words)
    #reverse each individual list
    nums.reverse()
    words.reverse()
    out_str = ""
    for i in range(0,len(nums)):
        #print(i)
        out_str += "{} {} ".format(nums[i],words[i])
    return out_str.strip()

#///////////
#API Calls
#///////////
def ping(server_url,headers,pubkey=None,signature=None):
    if not (pubkey==None and signature == None):
        payload = {
            "pubkey":pubkey,
            "signature":signature
        }
    else:
        payload=""

    response = invokeAPI(server_url,"ping",headers, payload)
    if response["signature"] == "ok":
        return 0
    elif response["signature"] == "Unknown pubkey":
        return 2
    elif response["signature"] == "signature error":
        return 3
    elif response["signature"] == "n/a":
        if response["response"] == "ok":
            return True
        else:
            return False
    else:
        print(json.dumps(response,indent=4))
        return 1

def addPubkey(headers,username,pubkey,signature):

    payload={
            "username":username,
            "pubkey":pubkey,
            "signature":signature
        }
    
    response = invokeAPI(LOGIN_SERVER_URL,"add_pubkey",headers,payload)

    return response

def updateUserKeysInDB(username,publickey,privatekey):
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    userList = SelectQueryToSingleList(c.fetchall())
    if username in userList:
        # Update values in table
        c.execute("""UPDATE Users
            SET
                publicKey=?,
                privateKey=?
            WHERE
                username=?
            """,
            (publickey,privatekey,username,))
    else:
        # Add new user to table
        c.execute("""INSERT INTO Users(username, publicKey, privateKey)
                            values(?,?,?)""",
                            (username,publickey,privatekey),)
    conn.commit()
    conn.close()

def updateActiveUsers(headers):
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    try:
        response = invokeAPI(LOGIN_SERVER_URL,'list_users',headers)
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
    else:
        activeUserList = response["users"]
        activeUsernames = []
        c.execute("SELECT username FROM Users")
        currentUserList = SelectQueryToSingleList(c.fetchall())
        for user in activeUserList:
            activeUsernames.append(user["username"])
            if user["username"] in currentUserList:
                # Update values in table
                c.execute("""UPDATE Users
                    SET
                        networkAddress=?,
                        status=?, 
                        publicKey=?, 
                        lastSeenTime=?, 
                        lastLocation=?
                    WHERE
                        username=?
                    """,
                    (user["connection_address"],user["status"],user["incoming_pubkey"],
                    user["connection_updated_at"],user["connection_location"],user["username"],))
            else:
                # Add new user to table
                c.execute("""INSERT INTO Users(username, networkAddress, status, publicKey, lastSeenTime, lastLocation)
                            values(?,?,?,?,?,?)""",
                            [user["username"],user["connection_address"],user["status"],user["incoming_pubkey"],
                            user["connection_updated_at"],user["connection_location"]],)

        # Set all users in the DB but not active to 'offline'
        for user in currentUserList:
            if user not in activeUsernames:
                # Set status to offline
                c.execute("""
                UPDATE Users
                SET
                    status='offline'
                WHERE username=?
                """, (user,))

    conn.commit()
    conn.close()

def getLoginServerRecord(headers,pubkey):
    try:
        response = invokeAPI(LOGIN_SERVER_URL,'check_pubkey?pubkey='+pubkey,headers)
    except urllib.error.HTTPError as err:
        print("Error code: " + str(err.code))
        return str(err.code)
    else:
        return response["loginserver_record"]

def reportToLoginServer(headers,pubkey,url,connectionLocation=2,status="online"):

    response = invokeAPI(LOGIN_SERVER_URL,"report",headers,payload={
            "connection_address":url,
            "connection_location":str(connectionLocation),
            "incoming_pubkey":pubkey,
            "status":status
        })

    return response

def getAPIKey(server_url, headers, **kwargs):
    """
    This function loads an API key from the central login server.
    
    Keyword Arguments:
    server_url : string
    headers : json
    
    Returns:
    api_key : string
    """
    response = invokeAPI(server_url,"load_new_apikey",headers)
    try:
        server_response = response["response"]
    except TypeError:
        return None
    else:
        if server_response == "ok":
            return response["api_key"]
        else:
            return None

def getPrivateData(headers):
    """
    This function loads private from the specified server.

    Keyword Arguments:
    server_url -- The url to get private data from
    headers -- Headers to send along with urllib request

    Returns:
    privatedata : JSON
    """
    response = invokeAPI(LOGIN_SERVER_URL,"get_privatedata",headers)
    if response["response"] == "ok":
        return response["privatedata"]
    elif response["response"] == "no privatedata available":
        return 1
    else:
        return None

def addPrivateData(privkey,headers,password,userPrefs,loginrecord,time):
    """
    This generates and adds private data to the central login server

    Keyword Arguments:
    privkey -- Public key
    headers -- Header to send with request
    payload -- Paylod to send with request
    password -- Password to encrypt private data with
    userPrefs -- Preferences that make up private data

    Returns:
    response -- Response from the login server
    """
    privatedata = generatePrivateData(password,userPrefs)
    signature = generateSignature(privkey,
                privatedata+loginrecord+time)

    payload = {
        "privatedata":privatedata,
        "loginserver_record":loginrecord,
        "client_saved_at":time,
        "signature":signature
    }

    print(json.dumps(payload,indent=4))

    response = invokeAPI(LOGIN_SERVER_URL,"add_privatedata",headers,payload)

    return response

if __name__=="__main__":
    print("This is a helper file")
    
    conn = sqlite3.connect("static/db/users.db")
    c = conn.cursor()
    c.execute("""
    SELECT username,ip,port FROM users WHERE username='max'""")
    rows = c.fetchall()
    users = []
    for x in rows:
        users.append(x[0])
    print(rows)
    print(users)
    #foo(a=1,b=4,random=12312312,other=21312)
    conn.commit()
    conn.close()