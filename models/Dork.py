'''
Created on Mar 12, 2012

@author: hathcox

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


from sqlalchemy import Column, ForeignKey, DateTime
from sqlalchemy.orm import synonym, relationship, backref
from models import dbsession, User, Tag, dork_tag_table
from sqlalchemy.types import Unicode, Integer, Boolean
from models.BaseObject import BaseObject
from string import ascii_letters, digits
from datetime import datetime


class Dork(BaseObject):
    ''' This is what the site is all about'''
    _title = Column(Unicode(64), unique=True, nullable=False)
    title = synonym('_title', descriptor=property(
        lambda self: self._title,
        lambda self, title: setattr(
            self, '_title', self.__class__.filter_string(title, " _-"))
    ))
    description = Column(Unicode(1024), nullable=False)
    submited_date = Column(DateTime, default=datetime.now)
    tags = relationship("Tag", secondary=dork_tag_table)
    submitted_user_id = Column(Integer, ForeignKey('user.id'))

    @classmethod
    def by_id(cls, uid):
        ''' Return the object whose user id is uid '''
        return dbsession.query(cls).filter_by(id=unicode(uid)).first()

    @classmethod
    def by_title(cls, title):
        ''' Returns the Dork object by the title '''
        return dbsession.query(cls).filter_by(title=unicode(title)).first()

    @classmethod
    def get_top(cls):
        ''' Returns the top 25 dorks '''
        return dbsession.query(cls).all()[:25]

    @classmethod
    def search_all(cls, search):
        return dbsession.query(cls).filter(cls.description.like('%' + search + '%')).all()
 
    @classmethod
    def search_by_tag(cls, tag, search):
        tag_dorks =  set(dbsession.query(cls).filter_by(tag in cls.tags).all())
        similair_dorks = set(dbsession.query(cls).filter(cls.description.like('%' + search + '%')).all())
        totalDorks = tag_dorks.intersection(similair_dorks)
        return totalDorks

    @classmethod
    def filter_string(cls, string, extra_chars=''):
        char_white_list = ascii_letters + digits + extra_chars
        return filter(lambda char: char in char_white_list, string)