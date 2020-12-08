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

logging.basicConfig(level=logging.DEBUG, filename='artifactory-module.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('artifactory')

class ArtifactoryRepo(object):
## https://www.jfrog.com/confluence/display/JFROG/Repository+Configuration+JSON
  def __init__(self, module):
    self.logger = logging.getLogger('ArtifactoryUser')
    self.logger.debug("init")
    self.module = module
    params = module.params
    self.api_username = params.get('api_username')
    self.api_password = params.get('api_password')
    self.api_base = params.get('api_base')
    self.currentrepo = None
    self.state = params['state']
    self.key = module.params.get('key')

    #ToDo: improve url building
    self.link = "{}/api/repositories/{}".format(self.api_base, self.key)
    self.logger.debug("init self.link: {}".format(self.link)) 

  def exists(self): 
    self.logger.debug("exists") 
    return self.get() is not None

  def get(self):
    self.logger.debug("get") 
    if self.currentrepo is not None:
      self.logger.debug("Using cached repo") 
      return self.currentrepo

    try:
      resp = open_url(
        url= self.link,
        force_basic_auth=True,
        url_username = self.api_username,
        url_password = self.api_password,
        )

      if resp.status == 200:
        self.currentrepo = json.loads(resp.read())
        return self.currentrepo
    except urllib_request.HTTPError as e:
      ## Repo returns 400 (User returned 404) Does not exist -- that can be a good thing
      if e.status == 400:
        self.currentrepo = None
        return None

      rawResponse = e.read()
      self.logger.error("Unexpected Get Response: {}".format(rawResponse))
      self.logger.error("Unexpected Get Response: {}".format(self.link))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message

    except Exception as e:
      self.module.fail_json(msg=to_native(e), function="Get Repo", exception=traceback.format_exc())

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
        self.module.fail_json(msg="Delete request returned unexpected status. connecting to '{}'. - Status {}.".format(self.link, resp.status))
    except urllib_request.HTTPError as e:
      rawResponse = e.read()
      self.logger.error("Response: {}".format(rawResponse))
      self.module.fail_json(url=self.link, status=e.status, msg=rawResponse) #json.load(rawResponse).errors[0].message

  def update(self):
    self.logger.debug("update")

    payload = {
      "key": self.key,
    }

    changed = False

    description = self.module.params.get('description')
    if description is not None and self.currentrepo.get('description') != description:
      changed = True
      self.logger.debug("Setting description to {}".format(description))
      payload['description'] = description

    if self.module.check_mode:
      self.logger.debug("Check Mode!")
      self.module.exit_json(changed=changed , check=True, payload=payload )

    if not changed:
      self.module.exit_json(changed=False)

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
      "key":      self.key,
      "rclass":    self.module.params['rclass'],
      "packageType": self.module.params['packageType']
    }

# ToDo: Add optional settings
#    admin = self.module.params.get('admin')
#    if admin is not None:
#      self.logger.debug("Setting Admin to {}".format(admin))
#      payload['admin'] = admin

    if self.module.check_mode:
      self.logger.debug("Check Mode!")
      self.module.exit_json(changed=True, created=True, check=True, payload=payload )
    try:
      ## ToDo: Support check
      resp = open_url(
        url= self.link,
        method='PUT',
        headers = {"Content-Type" : "application/json"},
        force_basic_auth=True,
        url_username = self.api_username,
        url_password = self.api_password,
        data = json.dumps(payload)
      )

      self.logger.debug("response status: {}".format(resp.status))
      if resp.status == 200:  # Created
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
      key              = dict(type='str', required=True),
      rclass           = dict(require=True, choices=['local', 'remote', 'virtual']),
      packageType      = dict(default='generic', require=False, choices=["alpine", "maven", "gradle", "ivy", "sbt", "helm", "cocoapods", "opkg", "rpm", "nuget", "cran", "gems", "npm", "bower", "debian", "composer", "pypi", "docker", "vagrant", "gitlfs", "go", "yum", "conan", "chef", "puppet", "generic"]),
      description      = dict(type='str', required=False),
      notes            = dict(type='str', required=False),
      includesPattern  = dict(type='str', required=False),
      excludesPattern  = dict(type='str', required=False),
      calculateYumMetadata = dict(require=False, type='bool')
#todo  groups(required=False, type='list')
    ),
    supports_check_mode=True
  )

  #run_module()
  artifactory_repo = ArtifactoryRepo(module=module)
  if module.params.get('state') == 'present':
    if artifactory_repo.exists():
      artifactory_repo.update()
      module.exit_json(msg='Update Repo')
    else:
      artifactory_repo.new()
      module.exit_json(changed=True, msg='Created a new repo')

  # Delete User
  if module.params.get('state') == 'absent':
    if artifactory_repo.exists():
      #User does not already exist
      artifactory_repo.delete()
      module.exit_json(changed=True, msg='Delete Repo')
    else:
      module.exit_json(changed=False, msg='Repo does not exist')

# Shouldn't get to here.
  module.exit_json(changed=False, created=False, user=artifactory_repo.currentuser)

if __name__ == '__main__':
  main()
