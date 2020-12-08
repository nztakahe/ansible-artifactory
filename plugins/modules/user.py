#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: artifactory users

short_description: Update users from Artifactory API

version_added: "0.0.1"

author:
  - Michael Menzies @mmenzies

requirements:

description:
  -  Get Users from Artifactory

options:
  api_base:
    description:
      - The server url
    required: true
    type: str
    aliases: [ server ]
  api_username:
    description:
      - The username to authenticate to the api
    required: true
    type: str
  api_password:
    description:
      - The password to authenticate to the api
    required: true
    type: str
  username:
    description:
      - The username wanted to add\change
'''
from ansible.module_utils.basic import AnsibleModule, missing_required_lib, env_fallback
from ansible.module_utils.urls import open_url, urllib_request
from ansible.module_utils.basic import AnsibleModule, json
from ansible.module_utils._text import to_native

import logging
import traceback

#logging.basicConfig(level=logging.DEBUG, filename='artifactory-module.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('artifactory')

class ArtifactoryUser(object):
  def __init__(self, module):
    self.logger = logging.getLogger('ArtifactoryUser')
    self.logger.debug("init")
    self.module = module
    params = module.params
    self.api_username = params.get('api_username')
    self.api_password = params.get('api_password')
    self.api_base = params.get('api_base')
    self.currentuser = None
    self.state = params['state']
    self.user = module.params.get('user')

    #ToDo: improve url building
    self.link = "{}/api/security/users/{}".format(self.api_base, self.user)
    self.logger.debug("init self.user: {}".format(self.user)) 
    self.logger.debug("init self.link: {}".format(self.link)) 

  def exists(self): 
    self.logger.debug("exists") 
    return self.get() is not None

  def get(self):
    self.logger.debug("get") 
    if self.currentuser is not None:
      self.logger.debug("Using cached user") 
      return self.currentuser

    try:
      resp = open_url(
        url= self.link,
        force_basic_auth=True,
        url_username = self.api_username,
        url_password = self.api_password,
        )

      if resp.status == 200:
        self.currentuser = json.loads(resp.read())
        return self.currentuser
    except urllib_request.HTTPError as e:
      ## User Does not exist -- that can be a good thing
      if e.status == 404:        
        self.currentuser = None
        return None

      #
      rawResponse = e.read()
      self.logger.error("Response: {}".format(rawResponse))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message

    except Exception as e:
      self.module.fail_json(msg=to_native(e), function="Get User", exception=traceback.format_exc())

#      else:
#        raise Exception("Get User HTTP Status Errors", self.link) #"Unexpected status getting user from '{}'. - Status {}.".format(link, resp.status)
        #self.module.fail_json(msg="Getting user connecting to '{}'. - Experienced error {}.".format(link, e))
#    except Exception as e:
#      raise Exception("Get User Exception") #"Unexpected status getting user from '{}'. - Status {}.".format(link, resp.status)
      #self.module.fail_json(msg="Getting user unknown error connecting to '{}'.".format(link))

  def delete(self):
    self.logger.debug("delete")
    if not self.exists():
      ## No need to delete something that exists
      self.module.exit_json(changed=False, deleted=True)
      return

    if self.module.check_mode:
      self.logger.debug("Check Mode!")
      self.module.exit_json(changed=True, deleted=True, check=True)

    try:
      resp = open_url(
        url = self.link,
        headers = {'Content-Type' : 'application/json'},
        method = 'DELETE',
        force_basic_auth = True,
        url_username = self.api_username,
        url_password = self.api_password,
        )
      if resp.status == 200:
        self.logger.info("Delete Looks successful to me")
        self.module.exit_json(changed=True, deleted=True)
      else:
        self.module.fail_json(msg="Delete User request returned unexpected status. connecting to '{}'. - Status {}.".format(self.link, resp.status))
    except urllib_request.HTTPError as e:
      rawResponse = e.read()
      self.logger.error("Response: {}".format(rawResponse))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message

  def update(self):
    self.logger.debug("update")

    payload = {
      "name": self.user,
    }

    changed = False

    password = self.module.params.get('password')
    if password is not None and self.module.params.get('update_password') == 'always':
      changed = True
      self.logger.debug("Update Password")
      payload['password'] = password
    self.logger.debug(payload)
    self.logger.debug(self.currentuser)

    email = self.module.params.get('email')
    if email is not None and self.currentuser.get('email') != email:
      self.logger.debug("Setting email to {}".format(email))
      payload['email'] = email

    admin = self.module.params.get('admin')
    if admin is not None and self.currentuser.get('admin') != admin:
      changed = True
      self.logger.debug("Setting Admin to {}".format(admin))
      payload['admin'] = admin
    self.logger.debug(payload)

    profileUpdatable = self.module.params.get('profileUpdatable')
    if profileUpdatable is not None and self.currentuser.get('profileUpdatable') != profileUpdatable:
      self.logger.debug("Setting profileUpdatable to {}".format(profileUpdatable))
      payload['profileUpdatable'] = profileUpdatable

    disableUIAccess = self.module.params.get('disableUIAccess')
    if disableUIAccess is not None and self.currentuser.get('disableUIAccess') != disableUIAccess:
      self.logger.debug("Setting disableUIAccess to {}".format(disableUIAccess))
      payload['disableUIAccess'] = disableUIAccess

    internalPasswordDisabled = self.module.params.get('internalPasswordDisabled')
    if internalPasswordDisabled is not None and self.currentuser.get('internalPasswordDisabled') != internalPasswordDisabled:
      self.logger.debug("Setting internalPasswordDisabled to {}".format(internalPasswordDisabled))
      payload['internalPasswordDisabled'] = internalPasswordDisabled

    if self.module.check_mode:
      self.logger.debug("Check Mode!")
      self.module.exit_json(changed=changed , check=True, payload=payload )

    try:
      ## ToDo: Support check
      resp = open_url(
        url= self.link,
        method='POST',
        headers = {"Content-Type" : "application/json"},
        force_basic_auth=True,
        url_username = self.api_username,
        url_password = self.api_password,
        data = json.dumps(payload)
      )

      self.logger.debug("response status: {}".format(resp.status))
      if resp.status == 200:  # Updated
        self.module.exit_json(changed=True, created=True)
      else:
        self.module.fail_json(msg="New User: unexpected status. connecting to '{}'. - Status {}.".format(self.link, resp.status))
    except urllib_request.HTTPError as e:
      rawResponse = e.read()
      self.logger.error("Response: {}".format(rawResponse))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message
    except Exception as e:
      self.module.fail_json(msg=to_native(e), function="Create User", exception=traceback.format_exc())


  def new(self):
    self.logger.debug("new")

    payload = {
      "name": self.user,
      "email": "{}@localhost".format(self.user),
      "password": self.module.params['password']
    }

    admin = self.module.params.get('admin')
    if admin is not None:
      self.logger.debug("Setting Admin to {}".format(admin))
      payload['admin'] = admin

    profileUpdatable = self.module.params.get('profileUpdatable')
    if profileUpdatable is not None:
      self.logger.debug("Setting profileUpdatable to {}".format(profileUpdatable))
      payload['profileUpdatable'] = profileUpdatable

    disableUIAccess = self.module.params.get('disableUIAccess')
    if disableUIAccess is not None:
      self.logger.debug("Setting profileUpdatable to {}".format(disableUIAccess))
      payload['disableUIAccess'] = disableUIAccess

    internalPasswordDisabled = self.module.params.get('internalPasswordDisabled')
    if internalPasswordDisabled is not None:
      self.logger.debug("Setting profileUpdatable to {}".format(internalPasswordDisabled))
      payload['internalPasswordDisabled'] = internalPasswordDisabled

    h = {"Content-Type" : "application/json"}

    if self.module.check_mode:
      self.logger.debug("Check Mode!")
      self.module.exit_json(changed=True, created=True, check=True, payload=payload )
    try:
      ## ToDo: Support check
      resp = open_url(
        url= self.link,
        method='PUT',
        headers = h,
        force_basic_auth=True,
        url_username = self.api_username,
        url_password = self.api_password,
        data = json.dumps(payload)
      )

      self.logger.debug("response status: {}".format(resp.status))
      if resp.status == 201:  # Created
        self.module.exit_json(changed=True, created=True)
      else:
        self.module.fail_json(msg="New User: unexpected status. connecting to '{}'. - Status {}.".format(self.link, resp.status))
    except urllib_request.HTTPError as e:
      rawResponse = e.read()
      self.logger.error("Response: {}".format(rawResponse))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message
    except Exception as e:
      self.module.fail_json(msg=to_native(e), function="Create User", exception=traceback.format_exc())

def main():
  logger.info("Starting main")
  module = AnsibleModule(
    argument_spec=dict(
      api_base         = dict(type='str', required=False),
      api_username     = dict(type='str', required=False),
      api_password     = dict(type='str', required=False, no_log=True),
      state            = dict(default='present', choices=['present', 'absent']),
      user             = dict(type='str',required=True),
      password         = dict(require=False, no_log=True),
      update_password  = dict(default='on_create', choices=['on_create', 'always'], no_log=False),
      email            = dict(type='str', required=False),
      admin            = dict(required=False, type='bool'),
      profileUpdatable = dict(required=False, type='bool'),
      disableUIAccess  = dict(required=False, type='bool'),
      internalPasswordDisabled = dict(require=False, type='bool')
#todo  groups(required=False, type='list')
    ),
    supports_check_mode=True
  )

  #run_module()
  artifactory_user = ArtifactoryUser(module=module)
  if module.params.get('state') == 'present':
    if artifactory_user.exists():
      artifactory_user.update()
      module.exit_json(msg='Updated existing user')
    else:
      artifactory_user.new()
      module.exit_json(changed=True, msg='Created a new user')

  # Delete User
  if module.params.get('state') == 'absent':
    if artifactory_user.exists():
      #User does not already exist
      artifactory_user.delete()
      module.exit_json(changed=True, msg='Delete User')
    else:
      module.exit_json(changed=False, msg='User already doesnt exist')

# Shouldn't get to here.
  module.exit_json(changed=False, created=False, user=artifactory_user.currentuser)

if __name__ == '__main__':
  main()
