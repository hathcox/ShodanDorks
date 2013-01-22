# -*- coding: utf-8 -*-
'''
Created on June 23, 2012

@author: moloch

    Copyright [2012] [Redacted Labs]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
'''


import os
import sys
import models
import logging

from os import urandom, path
from base64 import b64encode
from models import dbsession
from modules.Menu import Menu
from modules.Recaptcha import Recaptcha
from libs.ConfigManager import ConfigManager as ConfigMan
from libs.Session import SessionManager
from tornado import netutil, options, process
from tornado.web import Application
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop, PeriodicCallback
from handlers.PublicHandlers import *
from handlers.ErrorHandlers import *
from handlers.UserHandlers import *

### Load configuration
config = ConfigMan.Instance()

### Setup static file handler
if config.static_cache:
    from handlers.StaticFileHandler import StaticFileHandler
else:
    from tornado.web import StaticFileHandler

### Application setup
app = Application([
                  # Static Handlers - Serves static CSS, JavaScript and
                  # image files
                  (r'/static/(.*)',
                      StaticFileHandler, {'path': 'static'}),

                  # User handlers - for logged in pages
                  (r'/submit', SubmitHandler, {'dbsession': dbsession}),

                  # Public handlers - Serves all public pages
                  (r'/', WelcomeHandler),
                  (r'/login', LoginHandler, {'dbsession': dbsession}),
                  (r'/register',
                      RegistrationHandler, {'dbsession': dbsession}),
                  (r'/about', AboutHandler),

                  # Error handlers - Serves error pages
                  (r'/403', UnauthorizedHandler),
                  (r'/robots.txt', RobotsHandler),
                  (r'/(.*).php(.*)', PhpHandler),
                  (r'/(.*)etc/passwd(.*)', PasswdHandler),
                  (r'/(.*)', NotFoundHandler)
                  ],

                  # Randomly generated 64-byte secret key
                  cookie_secret=b64encode(urandom(64)),

                  # Ip addresses that access the admin interface
                  admin_ips=config.admin_ips,

                  # Template directory
                  template_path='templates',

                  # Requests that do not pass @authorized will be
                  # redirected here
                  forbidden_url='/403',

                  # UI Modules
                  ui_modules={"Menu": Menu, "Recaptcha": Recaptcha},

                  # Enable XSRF forms (not optional)
                  xsrf_cookies=True,

                  # Milli-Seconds between session clean up
                  clean_up_timeout=int(60 * 1000),

                  # Debug mode
                  debug=config.debug,

                  # Application version
                  version='0.1'
                  )


def start_server():
    ''' Main entry point for the application '''
    sockets = netutil.bind_sockets(config.listen_port)
    server = HTTPServer(app)
    server.add_sockets(sockets)
    io_loop = IOLoop.instance()
    session_manager = SessionManager.Instance()
    session_clean_up = PeriodicCallback(
        session_manager.clean_up,
        app.settings['clean_up_timeout'],
        io_loop=io_loop
    )
    try:
        logging.info("Shodan Hacking is online.")
        io_loop.start()
        session_clean_up.start()
    except KeyboardInterrupt:
        logging.warn("Keyboard interrupt, shutdown everything!")
        session_clean_up.stop()
        io_loop.stop()
    except:
        logging.exception("Main I/O Loop threw an excetion!")
