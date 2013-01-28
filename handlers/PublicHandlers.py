# -*- coding: utf-8 -*-
'''
Created on Mar 13, 2012

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
import logging

from tornado.web import RequestHandler
from BaseHandlers import UserBaseHandler
from recaptcha.client import captcha
from libs.Form import Form
from libs.ConfigManager import ConfigManager
from libs.Session import SessionManager
from libs.SecurityDecorators import authenticated
from models import User, Dork, Tag, dbsession


class WelcomeHandler(RequestHandler):
    ''' Landing page '''

    def get(self, *args, **kwargs):
        ''' Renders the welcome page '''
        top_dorks = Dork.get_top()
        self.render("public/welcome.html", dorks=top_dorks, errors=None)

    def post(self, *args, **kwargs):
        ''' This will search for a specific dork '''
        # top_dorks = Dork.get_top()
        form = Form(search="Please enter a search")
        try:
            #Check to see if they selected  a tag
            tag_name = self.get_argument('tag')
            tag = Tag.by_name(tag_name)
        except:
            tag = None
        if form.validate(self.request.arguments):
            if tag == None:
                #Search for all dorks
                top_dorks = Dork.search_all(self.get_argument('search'))
                self.render("public/welcome.html", dorks=top_dorks, errors=None)
            else:
                #Search for dorks with only that tag
                top_dorks = Dork.search_by_tag(tag, self.get_argument('search'))
                self.render("public/welcome.html", dorks=top_dorks, errors=None)
        else:
            self.render("public/welcome.html", dorks=top_dorks, errors=['Please enter a Search'])


class LoginHandler(RequestHandler):
    ''' Handles the login progress '''

    def initialize(self, dbsession):
        self.dbsession = dbsession
        self.config = ConfigManager.Instance()

    def get(self, *args, **kwargs):
        ''' Renders the login page '''
        self.render("public/login.html", errors=None)

    def post(self, *args, **kwargs):
        ''' Checks login creds '''
        form = Form(
            username="Please enter a username",
            password="Please enter a password",
            recaptcha_challenge_field="Invalid captcha",
            recaptcha_response_field="Invalid captcha",
        )
        if not form.validate(self.request.arguments):
            self.render("public/login.html", errors=form.errors)
        elif self.check_recaptcha():
            user = User.by_user_name(self.get_argument('username'))
            if user != None and user.validate_password(self.get_argument('password')):
                self.successful_login(user)
                self.redirect('/')
            else:
                self.failed_login()
        else:
            self.render(
                'public/login.html', errors=["Invalid captcha, try again"])

    def check_recaptcha(self):
        ''' Checks recaptcha '''
        if self.config.recaptcha_enable:
            response = None
            try:
                response = captcha.submit(
                    self.get_argument('recaptcha_challenge_field'),
                    self.get_argument('recaptcha_response_field'),
                    self.config.recaptcha_private_key,
                    self.request.remote_ip
                )
            except:
                logging.exception("Recaptcha API called failed")
            if response != None and response.is_valid:
                return True
            else:
                return False
        else:
            return True

    def successful_login(self, user):
        ''' Called when a user successfully authenticates '''
        logging.info("Successful login: %s from %s" %
                     (user.user_name, self.request.remote_ip))
        session_manager = SessionManager.Instance()
        sid, session = session_manager.start_session()
        self.set_secure_cookie(
            name='auth', value=str(sid), expires_days=1, HttpOnly=True)
        session.data['user_name'] = str(user.user_name)
        session.data['ip'] = str(self.request.remote_ip)
        if user.has_permission('admin'):
            session.data['menu'] = "admin"
        else:
            session.data['menu'] = "user"

    def failed_login(self):
        ''' Called when someone fails to login '''
        logging.info("Failed login attempt from %s" % self.request.remote_ip)
        self.render('public/login.html',
                    errors=["Failed login attempt, try again"])


class RegistrationHandler(RequestHandler):
    ''' Handles the user registration process '''

    def initialize(self, dbsession):
        self.dbsession = dbsession
        self.config = ConfigManager.Instance()

    def get(self, *args, **kwargs):
        ''' Renders registration page '''
        self.render("public/registration.html", errors=None)

    def post(self, *args, **kwargs):
        ''' Attempts to create an account '''
        form = Form(
            username="Please enter a username",
            pass1="Please enter a password",
            pass2="Please confirm your password",
            recaptcha_challenge_field="Invalid captcha",
            recaptcha_response_field="Invalid captcha",
        )
        if not form.validate(self.request.arguments):
            self.render("public/registration.html", errors=form.errors)
        elif self.check_recaptcha():
            user_name = self.get_argument('username')
            if User.by_user_name(user_name) != None:
                self.render('public/registration.html',
                            errors=['Account name already taken'])
            elif len(user_name) < 3 or 15 < len(user_name):
                self.render('public/registration.html',
                            errors=['Username must be 3-15 characters'])
            elif not self.get_argument('pass1') == self.get_argument('pass2'):
                self.render('public/registration.html',
                            errors=['Passwords do not match'])
            elif not (12 <= len(self.get_argument('pass1')) <= 100):
                self.render('public/registration.html',
                            errors=['Password must be 12-100 characters'])
            else:
                user = self.create_user(user_name, self.get_argument('pass1'))
                self.render(
                    "public/account_created.html", user_name=user.user_name)
        else:
            self.render("public/registration.html",
                        errors=['Invalid captcha'])

    def create_user(self, username, password):
        user = User(
            user_name=unicode(username),
        )
        # Create user, init class variables
        self.dbsession.add(user)
        self.dbsession.flush()
        # Set password for user
        user.password = password
        self.dbsession.add(user)
        self.dbsession.flush()
        return user

    def check_recaptcha(self):
        ''' Checks recaptcha '''
        if self.config.recaptcha_enable:
            response = None
            try:
                response = captcha.submit(
                    self.get_argument('recaptcha_challenge_field'),
                    self.get_argument('recaptcha_response_field'),
                    self.config.recaptcha_private_key,
                    self.request.remote_ip
                )
            except:
                logging.exception("Recaptcha API called failed")
            if response != None and response.is_valid:
                return True
            else:
                return False
        else:
            return True


class AboutHandler(RequestHandler):

    def get(self, *args, **kwargs):
        ''' Renders the about page '''
        self.render("public/about.html")


class SubmitHandler(RequestHandler):

    def get(self, *args, **kwargs):
        try:
            session_manager = SessionManager.Instance()
            session = session_manager.get_session(
                self.get_secure_cookie('auth'), self.request.remote_ip)
            user = User.by_user_name(session.data['user_name'])
            if user != None:
                self.render('user/submit.html', errors=None, success=None)
            else:
                self.render('public/please_login.html')
        except Exception as e:
            logging.info(e)
            self.render('public/please_login.html')

    def post(self, *args, **kwargs):
        ''' Create the Dork in the system '''
        form = Form(
            title="Please enter a title",
            description="Please enter a Description"
        )

        if form.validate(self.request.arguments):
            old_dork = Dork.by_title(self.get_argument('title'))
            if old_dork:
                self.render('user/submit.html', errors=['A Dork by this title has already been submitted'], success=None)
            else:
                self.create_dork()
                self.render('user/submit.html', success='Successfully created new Dork', errors=None)
        else:
            self.render('user/submit.html', errors=form.errors, success=None)

    def create_dork(self):
        new_dork = Dork(
            title = self.get_argument('title'),
            description = self.get_argument('description')
            )
        dbsession.add(new_dork)
        dbsession.flush()


class TopHandler(RequestHandler):

    def get(self, *args, **kwargs):
        top_dorks = Dork.get_top()
        self.render('public/top_dorks.html', dorks=top_dorks)

    def post(self, *args, **kwargs):
        pass
