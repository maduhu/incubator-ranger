/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.authorization.cdap.authorizer;

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;


public class RangerCDAPAuthorizer implements Authorizer {
	private static final Log LOG  = LogFactory.getLog(RangerCDAPAuthorizer.class);

	private static final String   RANGER_PLUGIN_TYPE                      = "cdap";
	private static final String[] RANGER_PLUGIN_LIB_DIR                   = new String[] {"lib/ranger-cdap-plugin"};
	private static final String RANGER_CDAP_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.cdap.authorizer.RangerCDAPAuthorizer";

	private Authorizer rangerCDAPAuthorizerImpl = null;
	private static		RangerPluginClassLoader rangerPluginClassLoader   = null;

	public RangerCDAPAuthorizer() {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerCDAPAuthorizer.RangerCDAPAuthorizer()");
		}

		this.init();

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.RangerCDAPAuthorizer()");
		}
	}

	private void init(){
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerCDAPAuthorizer.init()");
		}

		try {

			rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

			@SuppressWarnings("unchecked")
			Class<Authorizer> cls = (Class<Authorizer>) Class.forName(RANGER_CDAP_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

			activatePluginClassLoader();

			rangerCDAPAuthorizerImpl = cls.newInstance();
		} catch (Exception e) {
			// check what need to be done
			LOG.error("Error Enabling RangerCDAPPlugin", e);
		} finally {
			deactivatePluginClassLoader();
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.init()");
		}
	}

	private void activatePluginClassLoader() {
		if(rangerPluginClassLoader != null) {
			rangerPluginClassLoader.activate();
		}
	}

	private void deactivatePluginClassLoader() {
		if(rangerPluginClassLoader != null) {
			rangerPluginClassLoader.deactivate();
		}
	}

	@Override
	public void initialize(AuthorizationContext authorizationContext) throws Exception {
		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerCDAPAuthorizer.configure(AuthorizationContext)");
		}

		try {
			activatePluginClassLoader();

			rangerCDAPAuthorizerImpl.initialize(authorizationContext);
		} finally {
			deactivatePluginClassLoader();
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.configure(AuthorizationContext)");
		}
	}

	@Override
	public void enforce(EntityId entityId, Principal principal, Action action) throws Exception {
		if(LOG.isDebugEnabled()) {
			LOG.debug(String.format("==> RangerCDAPAuthorizer.authorize(EntityId=%s, Principal=%s, Action=%s)", entityId,
															principal, action));
		}

		try {
			activatePluginClassLoader();

			rangerCDAPAuthorizerImpl.enforce(entityId, principal, action);
		} catch (UnauthorizedException e) {
			if(LOG.isDebugEnabled()) {
				LOG.debug("<== RangerCDAPAuthorizer.enforce: " + e.getMessage(), e);
				throw e;
			}
		} finally {
			deactivatePluginClassLoader();
		}
		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.enforce: Successful");
		}
	}

	@Override
	public void grant(EntityId entityId, Principal principal, java.util.Set<Action> set) throws Exception {
		if(LOG.isDebugEnabled()) {
			LOG.debug(String.format("==> RangerCDAPAuthorizer.grant(EntityId=%s, Principal=%s, Action=%s)", entityId,
															principal, set));
		}

		try {
			activatePluginClassLoader();

			rangerCDAPAuthorizerImpl.grant(entityId, principal, set);
		} finally {
			deactivatePluginClassLoader();
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.grant(...)");
		}
	}

	@Override
	public void revoke(EntityId entityId, Principal principal, java.util.Set<Action> set) throws Exception {

	}

	@Override
	public void revoke(EntityId entityId) throws Exception {

	}

	@Override
	public java.util.Set<Privilege> listPrivileges(Principal principal) throws Exception {
		return null;
	}

	@Override
	public void createRole(Role role) throws Exception {

	}

	@Override
	public void dropRole(Role role) throws Exception {

	}

	@Override
	public void addRoleToPrincipal(Role role, Principal principal) throws Exception {

	}

	@Override
	public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {

	}

	@Override
	public java.util.Set<Role> listRoles(Principal principal) throws Exception {
		return null;
	}

	@Override
	public java.util.Set<Role> listAllRoles() throws Exception {
		return null;
	}

	@Override
	public void destroy() throws Exception {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerCDAPAuthorizer.close()");
		}

		try {
			activatePluginClassLoader();

			rangerCDAPAuthorizerImpl.destroy();
		} finally {
			deactivatePluginClassLoader();
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerCDAPAuthorizer.close()");
		}
	}
}
