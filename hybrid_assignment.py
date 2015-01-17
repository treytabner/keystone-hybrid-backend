# Copyright 2014 Hewlett-Packard Development Company, L.P
# Copyright 2014 SUSE Linux Products GmbH
# Copyright 2015 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import

import ldap

from oslo.config import cfg
from keystone import config
from keystone.assignment.backends import ldap as ldap_assign_backend
from keystone.assignment.backends import sql as sql_assign
from keystone.identity.backends import ldap as ldap_ident_backend
from keystone.identity.backends import sql as sql_ident
from keystone.common import sql
from keystone.common import ldap as common_ldap
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log


LOG = log.getLogger(__name__)


hybrid_opts = [
    cfg.ListOpt('default_roles',
                default=['_member_', ],
                help='List of roles assigned by default to an LDAP user'),
    cfg.StrOpt('default_project',
               default='demo',
               help='Default project'),
    cfg.StrOpt('default_domain',
               default='default',
               help='Default domain'),
]

CONF = config.CONF
CONF.register_opts(hybrid_opts, 'ldap_hybrid')


class Assignment(sql_assign.Assignment):
    _default_roles = list()
    _default_project = None
    identity = sql_ident.Identity()
    ldap_assign = ldap_assign_backend.Assignment()
    ldap_ident = ldap_ident_backend.Identity()

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None, session=None):
        try:
            res = super(Assignment, self)._get_metadata(
                user_id, tenant_id, domain_id, group_id, session)
        except exception.MetadataNotFound:
            projects = self._list_projects(user_id)
            if tenant_id in [project['id'] for project in projects]:
                return {
                    'roles': [
                        {'id': role_id} for role_id in self.default_roles
                    ]
                }
            else:
                raise
        else:
            roles = res.get('roles', [])
            res['roles'] = roles + [
                {'id': role_id} for role_id in self.default_roles
            ]
            return res

    @property
    def default_project(self):
        if self._default_project is None:
            self._default_project = self.get_project_by_name(
                CONF.ldap_hybrid.default_project,
                CONF.ldap_hybrid.default_domain)
        return dict(self._default_project)

    @property
    def default_project_id(self):
        return self.default_project['id']

    @property
    def default_roles(self):
        if not self._default_roles:
            with sql.transaction() as session:
                query = session.query(sql_assign.Role)
                query = query.filter(sql_assign.Role.name.in_(
                    CONF.ldap_hybrid.default_roles))
                role_refs = query.all()

            if len(role_refs) != len(CONF.ldap_hybrid.default_roles):
                raise exception.RoleNotFound(
                    message=_('Could not find one or more roles: %s') %
                    ', '.join(CONF.ldap_hybrid.default_roles))

            self._default_roles = [role_ref.id for role_ref in role_refs]
        return self._default_roles

    def _list_projects(self, user_id):
        user_dn = self.ldap_ident.user._id_to_dn(user_id),
        results = self.ldap_assign.role._ldap_get_list(
                    self.ldap_assign.project.tree_dn, ldap.SCOPE_SUBTREE,
                    query_params={self.ldap_assign.role.member_attribute:
                                  user_dn[0]},
                    attrlist=[
                        CONF.ldap.project_id_attribute,
                        CONF.ldap.project_name_attribute,
                        CONF.ldap.project_desc_attribute,
                    ])
        projects = []
        for result in results:
            project = {
                'description': result[1].get(CONF.ldap.project_desc_attribute)[0],
                'domain_id': CONF.ldap_hybrid.default_domain,
                'enabled': True,
                'id': result[1].get(CONF.ldap.project_id_attribute)[0],
                'name': result[1].get(CONF.ldap.project_name_attribute)[0],
            }
            projects.append(project)
        return projects

    def list_projects_for_user(self, user_id, group_ids, hints):
        try:
            self.identity.get_user(user_id)
        except exception.UserNotFound:
            projects = self._list_projects(user_id)
            for project in projects:
                # Check to see if the project already exists
                try:
                    super(Assignment, self).get_project(project['id'])
                except:
                    # Create the project locally
                    try:
                        super(Assignment, self).create_project(project['id'],
                                                               project)
                    except:
                        # Don't worry if it can't be added
                        pass

                # Add the proper roles to the project
                for role_id in self.default_roles:
                    try:
                        super(Assignment, self).add_role_to_user_and_project(
                                user_id, project['id'], role_id)
                    except:
                        # Don't worry, the role probably has already been added
                        pass

        else:
            projects = super(Assignment, self).list_projects_for_user(
                user_id, group_ids, hints)

        # Make sure the default project is in the project list for the user
        # user_id
        for project in projects:
            if project['id'] == self.default_project_id:
                return projects

        if not projects:
            # Only add the default project if they aren't already assigned
            projects.append(self.default_project)

        return projects
