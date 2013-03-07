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


import thread
import logging

from models import dbsession, User, Permission, Dork, Tag
from handlers.BaseHandlers import AdminBaseHandler
from libs.Form import Form
from libs.SecurityDecorators import *
from string import ascii_letters, digits


class ManageUsersHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' Renders the manage users page '''
        self.render("admin/manage_users.html",
                    users=User.all_users())

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def post(self, *args, **kwargs):
        ''' Approves users '''
        try:
            user_name = self.get_argument("username")
        except:
            self.render("admin/error.html", errors=["User does not exist"])
        user = User.by_user_name(user_name)
        permission = Permission(
            permission_name='admin',
            user_id=user.id
        )
        self.dbsession.add(permission)
        self.dbsession.add(user)
        self.dbsession.flush()
        self.render("admin/approved_user.html", user=user)


class ManageDorksHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' Display all of the dorks in the system '''
        dorks = Dork.all()
        self.render("admin/manage_dorks.html", dorks=dorks)


class ManageTagsHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' Display all of the tags in the system '''
        tags = Tag.all()
        self.render("admin/manage_tags.html", tags=tags)

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def post(self, *args, **kwargs):
        ''' This is used to create new tags '''
        form = Form(name="Please enter a tag name")
        tags = Tag.all()
        if form.validate(self.request.arguments):
            self.create_tag()
            tags = Tag.all()
            self.render("admin/manage_tags.html", tags=tags)
        else:
            self.render("admin/manage_tags.html", tags=tags, errors=form.errors)

    def create_tag(self):
        tag = Tag(
            name = self.get_argument('name')
            )
        self.dbsession.add(tag)
        self.dbsession.flush()

class EditDorksHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' this will let you edit any given dork in the system '''
        pass

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def post(self, *args, **kwargs):
        pass

class DeleteDorksHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' This will let you delete a given dork from the system '''
        dorks = Dork.all()
        try:
            uuid = self.get_argument('dork')
            if uuid != None:
                dork = Dork.by_uuid(uuid)
                if dork != None:
                    self.dbsession.delete(dork)
                    dorks = Dork.all()
                    self.render("admin/manage_dorks.html", success="Successfuly deleted dork from the system", dorks=dorks)
                else:
                    self.render("admin/manage_dorks.html", errors="Please Select a Dork", dorks=dorks)
            else:
                self.render("admin/manage_dorks.html", errors="Please Select a Dork", dorks=dorks)
        except:
            self.render("admin/manage_dorks.html", errors="Invalid Dork Selected", dorks=dorks)
       
class DeleteTagsHandler(AdminBaseHandler):

    @authenticated
    @authorized('admin')
    @restrict_ip_address
    def get(self, *args, **kwargs):
        ''' This will let you delete a given tag from the system '''
        tags = Tag.all()
        try:
            uuid = self.get_argument('tag')
            if uuid != None:
                tag = Tag.by_uuid(uuid)
                if tag != None:
                    self.dbsession.delete(tag)
                    tags = Tag.all()
                    self.render("admin/manage_tags.html", success="Successfuly deleted tag from the system", tags=tags)
                else:
                    self.render("admin/manage_tags.html", errors="Please Select a Tag", tags=tags)
            else:
                self.render("admin/manage_tags.html", errors="Please Select a Tag", tags=tags)
        except Exception as e:
            self.render("admin/manage_tags.html", errors="Invalid Tag Selected", tags=tags)
       