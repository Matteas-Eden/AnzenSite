#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Client Webapp
    Current Author/Maintainer: Matt Eden (mede607@aucklanduni.ac.nz)
    Last Edited: May 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python3  (3.7.3 is the version I use)

import os
import cherrypy
import server
import socket
import sys

# The port we listen for connections on
LISTEN_PORT = 10100

def runMainApp(listen_ip="0.0.0.0"):
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1, #timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            # 'tools.sessions.storage_type': 'file',
            # 'tools.sessions.storage_path': '/tmp/mysessions',
        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        '/favicon.ico': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        },
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    cherrypy.tree.mount(server.API_receive(), "/api/", conf)
    cherrypy.tree.mount(server.API_send(), "/out/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Matteas Eden")
    print("         University of Auckland")
    print("   COMPSYS302 - Example client web app")
    print("========================================")                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
if __name__ == '__main__':
    if len(sys.argv) > 1:
        runMainApp(socket.gethostbyname(socket.gethostname()))
    else:
        runMainApp()