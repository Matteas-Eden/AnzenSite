import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import sqlite3
import socket
from datetime import datetime
from helperFuncs import *
from jinja2 import Environment, FileSystemLoader

import centralServerAPI

ENCODING = 'utf-8'
PRIVATE_DATA_PASSWORD = "3302"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
SELF_URL = "172.23.88.17" #deprecated
SELF_PORT = "10100"
SELF_NET_ADDRESS = CLIENT_IP + ":" + SELF_PORT
LOCATION = 2
EMPTY_USER_PREFS = {
    "prikeys":[],
    "blocked_pubkeys":[],
    "blocked_usernames":[],
    "blocked_message_signatures":[],
    "blocked_words":[],
    "favourite_message_signatures":[],
    "friends_usernames":[],
}

env = Environment(loader=FileSystemLoader(searchpath='static/html'))
LOGIN_SERVER_URL = "http://cs302.kiwi.land/api"


class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True'
    }

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        tmpl=env.get_template('errorPage.html')
        error = {
            "code":404,
            "message":"Requested page could not be found"
        }
        return tmpl.render(error=error)

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self,bad_attempt=0):
        username = cherrypy.session.get("username",None)
        if username == None:
            tmpl = env.get_template('loginPage.html')
            return tmpl.render(failedLoginAttempt=bad_attempt)
        else:
            # tmpl=env.get_template('homePage.html')
            # return tmpl.render(username=username)

            broadcasts = getBroadcastsFromDBForHTML()
            users = getUsersFromDBForHTML()
            friends = cherrypy.session.get("friends",None)
            blocklist = cherrypy.session.get("blocklist",None)
            tmpl=env.get_template('home.html')
            return tmpl.render(username=username,IP=CLIENT_IP,broadcasts=broadcasts,users=users,friends=friends,blocklist=blocklist)
        # return Page
        

    @cherrypy.expose
    def messages(self):
        username = cherrypy.session.get("username",None)
        if username == None:
            raise cherrypy.HTTPRedirect('/')
        friends = cherrypy.session.get("friends",None)
        messages = getMessagesFromDBForHTML(username)
        users = getUsersFromDBForHTML()
        blocklist = cherrypy.session.get("blocklist",None)
        tmpl = env.get_template('messages.html')
        return tmpl.render(username=username,IP=CLIENT_IP,messages=messages,users=users,friends=friends,blocklist=blocklist)

    @cherrypy.expose
    def login(self, bad_attempt = 0):
        tmpl = env.get_template('loginPage.html')
        return tmpl.render(failedLoginAttempt=bad_attempt)

    @cherrypy.expose
    def energize(self):
        tmpl = env.get_template('energizeGame.html')
        return tmpl.render()

    @cherrypy.expose
    def updateBroadcasts(self):
        broadcasts = getBroadcastsFromDBForHTML()
        tmpl = env.get_template("broadcasts.html")
        return tmpl.render(broadcasts=broadcasts)

    @cherrypy.expose
    def updateMessages(self):
        messages = getMessagesFromDBForHTML(username)
        tmpl = env.get_template("messages.html")
        return tmpl.render(messages=messages)

    @cherrypy.expose
    def updateUserList(self):
        user = getUsersFromDBForHTML()
        tmpl = env.get_template("users.html")
        return tmpl.render(users=users)
    
    # @cherrypy.expose
    # def sum(self, a=0, b=0, **kwargs): #All inputs are strings by default
    #     output = int(a)+int(b)
    #     return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """
        Steps:
        - Authorise user/pass against DB
        - Authenticate via ping
        - Report online status
        """
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)
        if error == 0:
            # centralServerAPI.readKeys()
            # centralServerAPI.ping(True)
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            reportToLoginServer(cherrypy.session["APIKeyHeader"], cherrypy.session["publicKey"],
                SELF_NET_ADDRESS,1,"offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

class API_receive(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True'
    }
    
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        tmpl=env.get_template('errorPage.html')
        error = {
            "code":404,
            "message":"Requested page could not be found"
        }
        return tmpl.render(error=error)

    @cherrypy.expose
    def ping_check(self):
        # print("CHERRY PY ID: ", cherrypy.session.id)
        response = {
            "response":"",
            "message":"",
            "my_time":str((datetime.now()).timestamp()),
            "my_active_usernames":""
        }
        expectedFormat = ["my_time","connection_address","connection_location"]
        try:
            received_data = json.loads(cherrypy.request.body.read().decode(ENCODING))
        except ValueError:
            response["response"] = "error"
            response["message"] = "Bad request; Your parameters must adhere to JSON"
        else:
            #Check received data adheres to the expected format
            if not checkDataMatchesFormat(received_data,expectedFormat):
                response["response"] = "error"
                response["message"] = "Bad format; A different format was expected, check the API doc"
                return json.dumps(response)

            response["response"] = "ok"
            #response["message"] = "No errors"

        return json.dumps(response)
    
    @cherrypy.expose
    def rx_broadcast(self):
        response = {
            "response":"",
            "message":""
        }
        expectedFormat = ["loginserver_record","message","sender_created_at","signature"]
        try:
            received_data = json.loads(cherrypy.request.body.read().decode(ENCODING))
        except ValueError:
            response["response"] = "error"
            response["message"] = "Bad request; Your parameters must adhere to JSON"
        else:
            #Check received data adheres to the expected format
            if not checkDataMatchesFormat(received_data,expectedFormat):
                response["response"] = "error"
                response["message"] = "Bad format; A different format was expected, check the API doc"
                return json.dumps(response)

            response["response"] = "ok"
            sender_details = received_data["loginserver_record"].split(",")
            sender_name = sender_details[0]
            sender_pubkey = sender_details[1]
            print(received_data["loginserver_record"].split(",")[0],received_data["message"])

            broadcast_db = {
                "username":sender_name,
                "publicKey":sender_pubkey,
                "message":received_data["message"],
                "timestamp":str((datetime.now()).timestamp()),
                "signature":received_data["signature"]
            }

            addBroadcastToDB(broadcast_db)

        return json.dumps(response)

    @cherrypy.expose
    def rx_privatemessage(self):
        # print("CHERRY PY ID: ", cherrypy.session.id)
        response = {
            "response":"",
            "message":""
        }
        expectedFormat = ["loginserver_record","target_pubkey","target_username",
        "encrypted_message","sender_created_at","signature"]
        try:
            received_data = json.loads(cherrypy.request.body.read().decode(ENCODING))
        except ValueError:
            response["response"] = "error"
            response["message"] = "Bad request; Your parameters must adhere to JSON"
        else: #payload
            #Check received data adheres to the expected format
            if not checkDataMatchesFormat(received_data,expectedFormat):
                response["response"] = "error"
                response["message"] = "Bad format; A different format was expected, check the API doc"
                return json.dumps(response)

            #Extract fields of the payload
            received_message = received_data["encrypted_message"]
            target_user = received_data["target_username"]
            target_pubkey = received_data["target_pubkey"]
            loginserver_record = received_data["loginserver_record"]
            sender_time = received_data["sender_created_at"]
            sender_signature = received_data["signature"]
            print("Received message: ", received_message)

            #Extract details of sender
            sender_details = loginserver_record.split(",")
            sender_name = sender_details[0]
            sender_pubkey = sender_details[1]

            #Verify the signature
            if not verifySignature(sender_signature,loginserver_record+target_pubkey+
            target_user+received_message+sender_time,sender_pubkey):
                response["response"] = "error"
                response["message"] = "Bad signature; signature does not match rest of payload"
                return json.dumps(response)

            # Get keys for target user from database
            conn = sqlite3.connect("static/db/users.db")
            c = conn.cursor()
            print('USER = "', target_user, '"')
            c.execute("""SELECT publicKey, privateKey, status
                        FROM users
                        WHERE username=?""",(target_user, ))
            rows = c.fetchall()
            conn.commit()
            conn.close()

            record = rows[0]
            print("Record: ", record)
            try:
                user_pubkey = record[0]
                user_privkey = record[1]
                status = record[2]
            except:
                response["response"] = "error"
                response["message"] = "Incomplete user data; Your message could not be decrypted because my server does not have sufficient information"

            #Verify that the sender used the right pubkey
            if not target_pubkey == user_pubkey:
                response["response"] = "error"
                response["message"] = "Bad pubkey; public key does not match target user"
                print(json.dumps(response,indent=4))
                return json.dumps(response)

            #Decrypt message
            try:
                decrypted_message = decryptMessage(received_message,user_privkey)
            except nacl.exceptions.CryptoError:
                print("Failed to decrypt private message for USER=", target_user)
                response["response"] = "error"
                response["message"] = "CryptoError; My server failed to decrypt your message"
                print(json.dumps(response,indent=4))
                return json.dumps(response)
            except:
                print("Failed to decrypt")
                print("Private key: ", user_privkey, "Type: ", type(user_privkey))

            print("Message: ", decrypted_message)

            response["response"] = "ok"
            print("Data: ", received_data)

            message_db = {
                "sendingUser":sender_name,
                "receivingUser":target_user,
                "message":decrypted_message,
                "timestamp":str((datetime.now()).timestamp()),
                "signature":sender_signature
            }

            addMessageToDB(message_db)

        return json.dumps(response)

    @cherrypy.expose
    def rx_groupmessage(self):
        response = {
            "response":"error",
            "message":"This endpoint has not been implemented"
        }
        return json.dumps(response)

    @cherrypy.expose
    def rx_groupinvite(self):
        response = {
            "response":"error",
            "message":"This endpoint has not been implemented"
        }
        return json.dumps(response)

    @cherrypy.expose
    def checkmessages(self):
        response = {
            "response":"error",
            "message":"This endpoint has not been implemented"
        }
        return json.dumps(response)

    @cherrypy.expose
    def list_apis(self):
        response = {
            "response":"error",
            "message":"This endpoint has not been implemented"
        }
        return json.dumps(response)

    @cherrypy.expose
    def list_users(self):
        #return centralServerAPI.listUsers(verbose=False)
        #Get users that are online or away
        conn = sqlite3.connect("static/db/users.db")
        c = conn.cursor()
        c.execute("""SELECT username, networkAddress, publicKey, lastSeenTime, lastLocation, status
                    FROM users
                    WHERE status='online' OR status='away'""")
        rows = c.fetchall()
        conn.commit()
        conn.close()

        #Filter the results
        rows = c.fetchall()
        userList = []
        for x in rows:
            user = {
                "username": x[0],
                "connection_address": x[1] + ":" + x[2],
                "connection_location": x[3],
                "incoming_pubkey": x[4],
                "connection_updated_at": x[5],
                "status": x[6]
            }
            userList.append(user)

        response = {
            "users" : userList,
            "response":"ok"
        }

        return json.dumps(response)

class API_send(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True'
    }

    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        tmpl=env.get_template('errorPage.html')
        error = {
            "code":404,
            "message":"Requested page could not be found"
        }
        return tmpl.render(error=error)

    @cherrypy.expose
    def ping_check(self):

        conn = sqlite3.connect("static/db/users.db")
        c = conn.cursor()
        c.execute("""SELECT networkAddress FROM users WHERE status='online'""")
        rows = c.fetchall()
        conn.commit()
        conn.close()

        userCount = 0
        successCount = 0
        time_now = str((datetime.now()).timestamp())

        for record in rows:
            if record[0] == None:
                continue
            url = "http://" + record[0] + "/api"
            print("Ping checking: " + url + "/ping_check")
            userCount += 1
            try:
                response = invokeAPI(url,'ping_check',cherrypy.session["APIKeyHeader"],payload={
                    "my_time":time_now,
                    "connection_address":str(CLIENT_IP),
                    "connection_location":1
                })
                if response["response"] == "ok":
                    successCount += 1
            except:
                pass

        data={
            "users_checked":userCount,
            "successful_checks":successCount,
            "success":"ok"
        }

        return json.dumps(data)

    @cherrypy.expose
    def broadcast(self,message):
        # print("CHERRY PY ID: ", cherrypy.session.id)
        print("Broadcasting!")
        # count = cherrypy.session.get('count', 0) + 1
        # cherrypy.session['count'] = count
        # response = {
        #     "message":message,
        #     "count":cherrypy.session['count']
        #     #"apikey":json.dumps(cherrypy.session["APIKeyHeader"])
        # }

        #Get time
        time_now = str((datetime.now()).timestamp())

        #Get login record using user's public key
        cherrypy.session["loginserver_record"] = getLoginServerRecord(cherrypy.session["APIKeyHeader"],cherrypy.session["publicKey"])

        #Generate signature
        signature = generateSignature(cherrypy.session['privateKey'],
            cherrypy.session["loginserver_record"]+message+time_now) 

        conn = sqlite3.connect("static/db/users.db")
        c = conn.cursor()
        c.execute("""SELECT networkAddress, username FROM users WHERE status='online'""")
        rows = c.fetchall()
        conn.commit()
        conn.close()

        broadcast_db = {
            "username":cherrypy.session["username"],
            "publicKey":cherrypy.session["loginserver_record"].split(",")[1],
            "message":message,
            "timestamp":time_now,
            "signature":signature
        }
        addBroadcastToDB(broadcast_db)

        userList = []
        successfulUserList = []

        for record in rows:
            if record[0] == None:
                continue
            url = "http://" + record[0] + "/api"
            print("Broadcasting to: " + url + "/rx_broadcast")
            userList.append(record[1])
            try:
                response = invokeAPI(url,'rx_broadcast',cherrypy.session["APIKeyHeader"],payload={
                    "message":message,
                    "loginserver_record":cherrypy.session["loginserver_record"],
                    "sender_created_at":time_now,
                    "signature":signature
                })
                if response["response"]=="ok":
                    successfulUserList.append(record[1])
            except:
                pass

        data = {
            "users_broadcast_to":userList,
            "users_successfully_broadcast":successfulUserList,
            "success":"ok"            
        }

        return json.dumps(data)

    @cherrypy.expose
    def privatemessage(self, message, dest_user):
        payload = {}

        #Get pubkey of requested user
        conn = sqlite3.connect("static/db/users.db")
        c = conn.cursor()
        c.execute("""SELECT publicKey, networkAddress FROM users WHERE username=?""",(dest_user,))
        rows = c.fetchall()
        conn.commit()
        conn.close()

        if len(rows) == 0:
            return [json.dumps(payload),"unknown_user"]
        
        record = rows[0]
        target_pubkey = record[0]
        network_address = record[1]

        if target_pubkey == None:
            return json.dumps(payload)
        
        #Encrypt message
        try:
            en_message = encryptMessage(message,target_pubkey)
        except:
            print("Actual public key: " + str(target_pubkey))
            return

        #Get current time
        time_now = str((datetime.now()).timestamp())

        #Session variables
        cherrypy.session["loginserver_record"] = getLoginServerRecord(cherrypy.session["APIKeyHeader"],cherrypy.session["publicKey"])

        #Generate signature
        signature = generateSignature(cherrypy.session["privateKey"],
        cherrypy.session["loginserver_record"]+target_pubkey+dest_user+en_message+time_now)

        payload = {
            "loginserver_record":cherrypy.session["loginserver_record"],
            "encrypted_message":en_message,
            "target_username":dest_user,
            "target_pubkey":target_pubkey,
            "sender_created_at":time_now,
            "signature":signature,
        }

        response = invokeAPI("http://" + network_address + "/api/", 'rx_privatemessage',
        cherrypy.session["APIKeyHeader"],payload=payload)

        message_db = {
            "sendingUser":cherrypy.session["username"],
            "receivingUser":dest_user,
            "message":message,
            "timestamp":time_now,
            "signature":signature
        }

        try:
            target_response = response["response"]
        except:
            print("Bad response from ", dest_user)
            return
        else:
            if target_response == "ok":
                addMessageToDB(message_db)
        
        return json.dumps(response)

    @cherrypy.expose
    def ping(self):
        try:
            pubkey = cherrypy.session["publicKey"]
            APIKeyHeader = cherrypy.session.get["APIKeyHeader"]
        except:
            tmpl=env.get_template("errorPage.html")
            return tmpl.render(errorCode=403)
        else:
            signature = generateSignature(pubkey,pubkey)
            ping(LOGIN_SERVER_URL,APIKeyHeader,pubkey,signature)
            return {"response":"ok"}

    @cherrypy.expose
    def listusers(self):
        updateActiveUsers(cherrypy.session["APIKeyHeader"])
        response = {
            "success":"ok"
        }
        return json.dumps(response)

    # @cherrypy.expose
    # def getPrivateData(self):
    #     updateActiveUsers(cherrypy.session["APIKeyHeader"])
    #     return "success"

    @cherrypy.expose
    def report(self,connectionLocation=0,status="online"):
        """
        The purpose of this function is to implement /api/report, which involves sending
        a signal to the login server to update.

        Keyword Arguments:
        connectionLocation -- The location of the reporting user, defaults to 2
        status -- The status of the reporting user

        Returns:
        boolean literal
        """
        # response = invokeAPI(LOGIN_SERVER_URL,"report",cherrypy.session["APIKeyHeader"],payload={
        #     "connection_address":SELF_URL,
        #     "connection_location":str(connectionLocation),
        #     "incoming_pubkey":cherrypy.session["publicKey"],
        #     "status":status
        # })

        response = reportToLoginServer(cherrypy.session["APIKeyHeader"], cherrypy.session["publicKey"],
                SELF_NET_ADDRESS,connectionLocation,status)

        return json.dumps(response)

    @cherrypy.expose
    def checkmessages(self):

        # Format of response expected
        expectedFormat = ["response","broadcasts","private_messages"]

        conn = sqlite3.connect("static/db/users.db")
        c = conn.cursor()
        c.execute("SELECT networkAddress FROM users")
        rows = c.fetchall()

        try:
            c.execute("SELECT lastSeenTime FROM users WHERE username=?",(cherrypy.session["username"],))
        except KeyError:
            print("Failed to retrieve username from cherrypy.session")
            return 1

        try:
            timeToCheck = c.fetchall()[0][0]
        except:
            print("No time found for: ", cherrypy.session["username"])
            return 1

        conn.commit()
        conn.close()

        for record in rows:
            net_address = record[0]
            if not record == None:
                response = invokeAPI(net_address+"/api",'checkmessages?='+str(timeToCheck),cherrypy.session["APIKeyHeader"])
                if response["response"] == "error":
                    print("Received error from: ", net_address)
                else:
                    if checkDataMatchesFormat(response,expectedFormat):
                        for b in response["broadcasts"]:
                            addBroadcastToDB(b)
                        for m in response["private_messages"]:
                            addMessageToDB(m)

###
### Functions only after here
###

def authoriseUserLogin(username, password):
    """
    Authorises a username/password combo with the login server

    Keyword Arguments:
    username -- The username
    password -- The password

    Returns:
    0 -- Authorised User
    1 -- Failed to authorise user
    """
    # username = "mede607"
    # password = "Matteas-Eden_489439263"
    print("Log on attempt from {0}:{1}".format(username, password))
    
    """     
    - Construct the header from user/pass
    - Then construct the header from user & apikey
    - Call ping on the server's endpoint using the above header
    - Get the private key from the private data, if it exists
    - If there isn't a private key, generate one and add it
    - Ping using the public key and a signature
    - Report online to central server
    """
    basicHeader = createBasicHTTPHeader(username=username,password=password)
    session_api_key = getAPIKey(LOGIN_SERVER_URL,basicHeader)
    if session_api_key == None:
        return 1

    APIKeyHeader = createAPIKeyHTTPHeader(username,session_api_key)
    if ping(LOGIN_SERVER_URL,APIKeyHeader) == False:
        print("Server failed to authenticate")
        return 1

    #print(alt_ping(LOGIN_SERVER_URL,APIKeyHeader))

    privateData = getPrivateData(APIKeyHeader)
    if privateData == 1:
        print("No private data available")
        # return 1
        #Generate private data
        userKeys = createNewPrivateDataForUser(username, APIKeyHeader)

    elif privateData == None:
        #Different error
        print("Couldn't reach login server")
        return 1
    else:
        try:
            userPrefs = decryptPrivateData(privateData,PRIVATE_DATA_PASSWORD)
        except:
            #Private data not valid
            print("Private data not in a valid format")
            #return 1
            userKeys = createNewPrivateDataForUser(username, APIKeyHeader)
        else:
            if not userPrefs == None:
                if len(userPrefs["prikeys"]) >= 0:
                    privateKey = nacl.signing.SigningKey(userPrefs["prikeys"][0], encoder=nacl.encoding.HexEncoder)
                    userKeys = {
                        "pubkey":privateKey.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode(ENCODING),
                        "privkey":privateKey.encode(encoder=nacl.encoding.HexEncoder).decode(ENCODING)
                    }
                    cherrypy.session["friends"] = userPrefs["friends_usernames"]
                    cherrypy.session["blocklist"]={
                        "pubkey":userPrefs["blocked_pubkeys"],
                        "words":userPrefs["blocked_words"],
                        "users":userPrefs["blocked_usernames"],
                        "messages":userPrefs["blocked_message_signatures"]
                    }
                else:
                    print("Private key not found")
                    # return 1
                    userKeys = createNewPrivateDataForUser(username,APIKeyHeader)
            else:
                print("Issue with decrypting private data")
                # return 1
                userKeys = createNewPrivateDataForUser(username,APIKeyHeader)

    if reportToLoginServer(APIKeyHeader,userKeys["pubkey"],SELF_URL,LOCATION,"online"):
        cherrypy.session["APIKeyHeader"] = APIKeyHeader
        cherrypy.session["publicKey"] = userKeys["pubkey"]
        cherrypy.session["privateKey"] = userKeys["privkey"] #this session variable doesn't work

        #Write user & keys to database
        updateUserKeysInDB(username,userKeys["pubkey"],userKeys["privkey"])
        print("Successful logon")
        return 0

    return 1

def createNewPrivateDataForUser(username,APIKeyHeader):
    """
    This function creates new private data for a user who has no previous valid
    private data to access.

    First, public and private keys are created. Then, the public key is registered
    with the login server. This public key is used to report to the server, and then
    the a loginserver_record is requested from the server. A function is then called to
    generate and add the new private data for the user to the login server.
    //Private data cannot be added to login server due to unknown error with signature

    Keyword Arguments:
    username -- The username
    APIKeyHeader -- The header to be used in API calls

    Returns:
    user_keys -- The new public/private keys for the user
    """
    user_keys = createKeysForUser()
    time_now = str((datetime.now().timestamp()))

    addPubkey(APIKeyHeader,username,user_keys["pubkey"],
        generateSignature(user_keys["privkey"],user_keys["pubkey"]+username))

    res = reportToLoginServer(APIKeyHeader,user_keys["pubkey"],LOGIN_SERVER_URL,1,"online")
    print("/////REPORT//////")
    print(json.dumps(res,indent=4))
    print("/////END REPORT//////")

    print("1) APIKEYHEADER: ", APIKeyHeader)

    loginserver_record = getLoginServerRecord(APIKeyHeader,user_keys["pubkey"])

    print("2) APIKEYHEADER: ", APIKeyHeader)

    addPrivateData(user_keys["pubkey"],APIKeyHeader,password=PRIVATE_DATA_PASSWORD,
        userPrefs=EMPTY_USER_PREFS,loginrecord=loginserver_record,time=time_now)
    return user_keys