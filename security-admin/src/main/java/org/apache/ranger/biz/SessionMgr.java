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

 package org.apache.ranger.biz;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.apache.ranger.common.DateUtil;
import org.apache.ranger.common.HTTPUtil;
import org.apache.ranger.common.MessageEnums;
import org.apache.ranger.common.RESTErrorUtil;
import org.apache.ranger.common.RangerCommonEnums;
import org.apache.ranger.common.RangerConstants;
import org.apache.ranger.common.SearchCriteria;
import org.apache.ranger.common.StringUtil;
import org.apache.ranger.common.UserSessionBase;
import org.apache.ranger.db.RangerDaoManager;
import org.apache.ranger.entity.XXAuthSession;
import org.apache.ranger.entity.XXPortalUser;
import org.apache.ranger.entity.XXPortalUserRole;
import org.apache.ranger.entity.XXUser;
import org.apache.ranger.security.context.RangerContextHolder;
import org.apache.ranger.security.context.RangerSecurityContext;
import org.apache.ranger.security.listener.RangerHttpSessionListener;
import org.apache.ranger.security.web.filter.RangerSecurityContextFormationFilter;
import org.apache.ranger.service.AuthSessionService;
import org.apache.ranger.util.RestUtil;
import org.apache.ranger.view.VXAuthSession;
import org.apache.ranger.view.VXAuthSessionList;
import org.apache.ranger.view.VXLong;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
public class SessionMgr {

	static final Logger logger = Logger.getLogger(SessionMgr.class);

	@Autowired
	RESTErrorUtil restErrorUtil;
	
	@Autowired
	RangerDaoManager daoManager;

	@Autowired
	AuthSessionService authSessionService;

	@Autowired
	HTTPUtil httpUtil;

	@Autowired
	StringUtil stringUtil;
	
	public SessionMgr() {
		logger.debug("SessionManager created");
	}

	private static final Long SESSION_UPDATE_INTERVAL_IN_MILLIS = 30 * DateUtils.MILLIS_PER_MINUTE;

	public UserSessionBase processSuccessLogin(int authType, String userAgent) {
		return processSuccessLogin(authType, userAgent, null);
	}

	public UserSessionBase processSuccessLogin(int authType, String userAgent,
			HttpServletRequest httpRequest) {
		boolean newSessionCreation = true;
		UserSessionBase userSession = null;

		RangerSecurityContext context = RangerContextHolder.getSecurityContext();
		if (context != null) {
			userSession = context.getUserSession();
		}

		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		WebAuthenticationDetails details = (WebAuthenticationDetails) authentication
				.getDetails();

		String currentLoginId = authentication.getName();
		if (userSession != null) {
			if (validateUserSession(userSession, currentLoginId)) {
				newSessionCreation = false;
			}
		}

		if (newSessionCreation) {
			// Need to build the UserSession
			XXPortalUser gjUser = daoManager.getXXPortalUser().findByLoginId(currentLoginId);
			if (gjUser == null) {
				logger.error(
						"Error getting user for loginId=" + currentLoginId,
						new Exception());
				return null;
			}

			XXAuthSession gjAuthSession = new XXAuthSession();
			gjAuthSession.setLoginId(currentLoginId);
			gjAuthSession.setUserId(gjUser.getId());
			gjAuthSession.setAuthTime(DateUtil.getUTCDate());
			gjAuthSession.setAuthStatus(XXAuthSession.AUTH_STATUS_SUCCESS);
			gjAuthSession.setAuthType(authType);
			if (details != null) {
				gjAuthSession.setExtSessionId(details.getSessionId());
				gjAuthSession.setRequestIP(details.getRemoteAddress());
			}

			if (userAgent != null) {
				gjAuthSession.setRequestUserAgent(userAgent);
			}
			gjAuthSession.setDeviceType(httpUtil.getDeviceType(userAgent));
			HttpSession session = httpRequest.getSession();
			if (session != null) {
				if (session.getAttribute("auditLoginId") == null) {
					synchronized (session) {
						if (session.getAttribute("auditLoginId") == null) {
							gjAuthSession = storeAuthSession(gjAuthSession);
							session.setAttribute("auditLoginId", gjAuthSession.getId());
						}
					}
				}
			}

			userSession = new UserSessionBase();
			userSession.setXXPortalUser(gjUser);
			userSession.setXXAuthSession(gjAuthSession);

			resetUserSessionForProfiles(userSession);
			resetUserModulePermission(userSession);

			Calendar cal = Calendar.getInstance();
			if (details != null) {
				logger.info("Login Success: loginId=" + currentLoginId
						+ ", sessionId=" + gjAuthSession.getId()
						+ ", sessionId=" + details.getSessionId()
						+ ", requestId=" + details.getRemoteAddress()
						+ ", epoch=" + cal.getTimeInMillis());
			} else {
				logger.info("Login Success: loginId=" + currentLoginId
						+ ", sessionId=" + gjAuthSession.getId()
						+ ", details is null"
						+ ", epoch=" + cal.getTimeInMillis());
			}

		}

		return userSession;
	}

	public void resetUserModulePermission(UserSessionBase userSession) {

		XXUser xUser = daoManager.getXXUser().findByUserName(userSession.getLoginId());
		if (xUser != null) {
			List<String> permissionList = daoManager.getXXModuleDef().findAccessibleModulesByUserId(userSession.getUserId(), xUser.getId());
			CopyOnWriteArraySet<String> userPermissions = new CopyOnWriteArraySet<String>(permissionList);

			UserSessionBase.RangerUserPermission rangerUserPermission = userSession.getRangerUserPermission();

			if (rangerUserPermission == null) {
				rangerUserPermission = new UserSessionBase.RangerUserPermission();
			}

			rangerUserPermission.setUserPermissions(userPermissions);
			rangerUserPermission.setLastUpdatedTime(Calendar.getInstance().getTimeInMillis());
			userSession.setRangerUserPermission(rangerUserPermission);
			logger.info("UserSession Updated to set new Permissions to User: " + userSession.getLoginId());
		} else {
			logger.error("No XUser found with username: " + userSession.getLoginId() + "So Permission is not set for the user");
		}
	}

	public void resetUserSessionForProfiles(UserSessionBase userSession) {
		if (userSession == null) {
			// Nothing to reset
			return;
		}

		// Let's get the Current User Again
		String currentLoginId = userSession.getLoginId();

		XXPortalUser gjUser = daoManager.getXXPortalUser().findByLoginId(currentLoginId);
		userSession.setXXPortalUser(gjUser);

		setUserRoles(userSession);

	}

	private void setUserRoles(UserSessionBase userSession) {

		List<String> strRoleList = new ArrayList<String>();
		List<XXPortalUserRole> roleList = daoManager.getXXPortalUserRole().findByUserId(
				userSession.getUserId());
		for (XXPortalUserRole gjUserRole : roleList) {
			String userRole = gjUserRole.getUserRole();
			strRoleList.add(userRole);
		}

		if (strRoleList.contains(RangerConstants.ROLE_SYS_ADMIN)) {
			userSession.setUserAdmin(true);
			userSession.setKeyAdmin(false);
		} else if (strRoleList.contains(RangerConstants.ROLE_KEY_ADMIN)) {
			userSession.setKeyAdmin(true);
			userSession.setUserAdmin(false);
		} else if (strRoleList.size() == 1 && strRoleList.get(0).equals(RangerConstants.ROLE_USER)) {
			userSession.setKeyAdmin(false);
			userSession.setUserAdmin(false);
		}

		userSession.setUserRoleList(strRoleList);
	}

	public XXAuthSession processFailureLogin(int authStatus, int authType,
			String loginId, String remoteAddr, String sessionId) {
		XXAuthSession gjAuthSession = new XXAuthSession();
		gjAuthSession.setLoginId(loginId);
		gjAuthSession.setUserId(null);
		gjAuthSession.setAuthTime(DateUtil.getUTCDate());
		gjAuthSession.setAuthStatus(authStatus);
		gjAuthSession.setAuthType(authType);
		gjAuthSession.setDeviceType(RangerCommonEnums.DEVICE_UNKNOWN);
		gjAuthSession.setExtSessionId(sessionId);
		gjAuthSession.setRequestIP(remoteAddr);
		gjAuthSession.setRequestUserAgent(null);

		gjAuthSession = storeAuthSession(gjAuthSession);
		return gjAuthSession;
	}

	protected boolean validateUserSession(UserSessionBase userSession,
			String currentLoginId) {
		if (currentLoginId
				.equalsIgnoreCase(userSession.getXXPortalUser().getLoginId())) {
			return true;
		} else {
			logger.info(
					"loginId doesn't match loginId from HTTPSession. Will create new session. loginId="
							+ currentLoginId + ", userSession=" + userSession,
					new Exception());
			return false;
		}
	}

	@Transactional(readOnly = false, propagation = Propagation.REQUIRES_NEW)
	protected XXAuthSession storeAuthSession(XXAuthSession gjAuthSession) {
		// daoManager.getEntityManager().getTransaction().begin();
		XXAuthSession dbMAuthSession = daoManager.getXXAuthSession().create(
				gjAuthSession);
		// daoManager.getEntityManager().getTransaction().commit();
		return dbMAuthSession;
	}

	// non-WEB processing
	public UserSessionBase processStandaloneSuccessLogin(int authType,
			String ipAddress) {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();

		String currentLoginId = authentication.getName();

		// Need to build the UserSession
		XXPortalUser gjUser = daoManager.getXXPortalUser().findByLoginId(currentLoginId);
		if (gjUser == null) {
			logger.error("Error getting user for loginId=" + currentLoginId,
					new Exception());
			return null;
		}

		XXAuthSession gjAuthSession = new XXAuthSession();
		gjAuthSession.setLoginId(currentLoginId);
		gjAuthSession.setUserId(gjUser.getId());
		gjAuthSession.setAuthTime(DateUtil.getUTCDate());
		gjAuthSession.setAuthStatus(XXAuthSession.AUTH_STATUS_SUCCESS);
		gjAuthSession.setAuthType(authType);
		gjAuthSession.setDeviceType(RangerCommonEnums.DEVICE_UNKNOWN);
		gjAuthSession.setExtSessionId(null);
		gjAuthSession.setRequestIP(ipAddress);
		gjAuthSession.setRequestUserAgent(null);

		gjAuthSession = storeAuthSession(gjAuthSession);

		UserSessionBase userSession = new UserSessionBase();
		userSession.setXXPortalUser(gjUser);
		userSession.setXXAuthSession(gjAuthSession);

		// create context with user-session and set in thread-local
		RangerSecurityContext context = new RangerSecurityContext();
		context.setUserSession(userSession);
		RangerContextHolder.setSecurityContext(context);

		resetUserSessionForProfiles(userSession);
		resetUserModulePermission(userSession);

		return userSession;
	}

	/**
	 * @param searchCriteria
	 * @return
	 */
	public VXAuthSessionList searchAuthSessions(SearchCriteria searchCriteria) {

		if (searchCriteria == null) {
			searchCriteria = new SearchCriteria();
		}
		if (searchCriteria.getParamList() != null
				&& searchCriteria.getParamList().size() > 0) {	
			
			int clientTimeOffsetInMinute=RestUtil.getClientTimeOffset();
			java.util.Date temp = null;
			DateUtil dateUtil = new DateUtil();
			if (searchCriteria.getParamList().containsKey("startDate")) {
				temp = (java.util.Date) searchCriteria.getParamList().get(
						"startDate");
				temp = dateUtil.getDateFromGivenDate(temp, 0, 0, 0, 0);
				temp = dateUtil.addTimeOffset(temp, clientTimeOffsetInMinute);
				searchCriteria.getParamList().put("startDate", temp);
			}
			if (searchCriteria.getParamList().containsKey("endDate")) {
				temp = (java.util.Date) searchCriteria.getParamList().get(
						"endDate");
				temp = dateUtil.getDateFromGivenDate(temp, 0, 23, 59, 59);
				temp = dateUtil.addTimeOffset(temp, clientTimeOffsetInMinute);
				searchCriteria.getParamList().put("endDate", temp);
			}
		}
		
		return authSessionService.search(searchCriteria);
	}

	public VXLong countAuthSessions(SearchCriteria searchCriteria) {
		return authSessionService.getSearchCount(searchCriteria,
				AuthSessionService.AUTH_SESSION_SEARCH_FLDS);
	}

	public VXAuthSession getAuthSession(Long id) {
		return authSessionService.readResource(id);
	}

	public VXAuthSession getAuthSessionBySessionId(String authSessionId) {
		if(stringUtil.isEmpty(authSessionId)){
			throw restErrorUtil.createRESTException("Please provide the auth session id.", 
					MessageEnums.INVALID_INPUT_DATA);
		}
		
		XXAuthSession xXAuthSession = daoManager.getXXAuthSession()
				.getAuthSessionBySessionId(authSessionId);
		
		if(xXAuthSession==null){
			throw restErrorUtil.createRESTException("Please provide a valid "
					+ "session id.", MessageEnums.INVALID_INPUT_DATA);
		}
		
		VXAuthSession vXAuthSession = authSessionService.populateViewBean(xXAuthSession);
		return vXAuthSession;
	}
	
	public boolean isValidXAUser(String loginId) {
		XXPortalUser pUser = daoManager.getXXPortalUser().findByLoginId(loginId);
		if (pUser == null) {
			logger.error("Error getting user for loginId=" + loginId);
			return false;
		} else {
			logger.info(loginId+" is a valid user");
			return true;
		}
		
	}

	public CopyOnWriteArrayList<UserSessionBase> getActiveSessionsOnServer() {

		CopyOnWriteArrayList<HttpSession> activeHttpUserSessions = RangerHttpSessionListener.getActiveSessionOnServer();
		CopyOnWriteArrayList<UserSessionBase> activeRangerUserSessions = new CopyOnWriteArrayList<UserSessionBase>();

		if (CollectionUtils.isEmpty(activeHttpUserSessions)) {
			return activeRangerUserSessions;
		}

		for (HttpSession httpSession : activeHttpUserSessions) {

			if (httpSession.getAttribute(RangerSecurityContextFormationFilter.AKA_SC_SESSION_KEY) == null) {
				continue;
			}

			RangerSecurityContext securityContext = (RangerSecurityContext) httpSession.getAttribute(RangerSecurityContextFormationFilter.AKA_SC_SESSION_KEY);
			if (securityContext.getUserSession() != null) {
				activeRangerUserSessions.add(securityContext.getUserSession());
			}
		}

		return activeRangerUserSessions;
	}

	public Set<UserSessionBase> getActiveUserSessionsForPortalUserId(Long portalUserId) {
		CopyOnWriteArrayList<UserSessionBase> activeSessions = getActiveSessionsOnServer();

		if (CollectionUtils.isEmpty(activeSessions)) {
			return null;
		}

		Set<UserSessionBase> activeUserSessions = new HashSet<UserSessionBase>();
		for (UserSessionBase session : activeSessions) {
			if (session.getUserId().equals(portalUserId)) {
				activeUserSessions.add(session);
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("No Session Found with portalUserId: " + portalUserId);
		}
		return activeUserSessions;
	}

	public Set<UserSessionBase> getActiveUserSessionsForXUserId(Long xUserId) {
		XXPortalUser portalUser = daoManager.getXXPortalUser().findByXUserId(xUserId);
		if (portalUser != null) {
			return getActiveUserSessionsForPortalUserId(portalUser.getId());
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("Could not find corresponding portalUser for xUserId" + xUserId);
			}
			return null;
		}
	}

	public synchronized void refreshPermissionsIfNeeded(UserSessionBase userSession) {
		if (userSession != null) {
			Long lastUpdatedTime = (userSession.getRangerUserPermission() != null) ? userSession.getRangerUserPermission().getLastUpdatedTime() : null;
			if (lastUpdatedTime == null || (Calendar.getInstance().getTimeInMillis() - lastUpdatedTime) > SESSION_UPDATE_INTERVAL_IN_MILLIS) {
				this.resetUserModulePermission(userSession);
			}
		}
	}

}
