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

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Date;

public class RangerCDAPAuthorizer implements Authorizer {
  private static final Log logger = LogFactory
    .getLog(RangerCDAPAuthorizer.class);

  public static final String KEY_INSTANCE = "instance";

  public static final String ACCESS_TYPE_READ = "read";
  public static final String ACCESS_TYPE_WRITE = "write";
  public static final String ACCESS_TYPE_EXECUTE = "execute";
  public static final String ACCESS_TYPE_ADMIN = "admin";
  public static final String ACCESS_TYPE_ALL = "all";

  private static volatile RangerBasePlugin rangerPlugin = null;
  long lastLogTime = 0;
  int errorLogFreq = 30000; // Log after every 30 seconds

  public RangerCDAPAuthorizer() {
  }


  /**
   * @param action
   * @return
   */
  private String mapToRangerAccessType(Action action) {
    switch (action) {
      case READ:
        return ACCESS_TYPE_READ;
      case WRITE:
        return ACCESS_TYPE_WRITE;
      case EXECUTE:
        return ACCESS_TYPE_EXECUTE;
      case ADMIN:
        return ACCESS_TYPE_ADMIN;
      case ALL:
        return ACCESS_TYPE_ALL;
      default:
        return null;
    }
  }

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    if (rangerPlugin == null) {
      rangerPlugin = new RangerBasePlugin("cdap", "cdap");
      logger.info("Calling plugin.init()");
      rangerPlugin.init();

      RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
      rangerPlugin.setResultProcessor(auditHandler);
    }
  }

  @Override
  public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
    if (rangerPlugin == null) {
      MiscUtil.logErrorMessageByInterval(logger,
                                         "Authorizer is still not initialized");
      throw new RuntimeException("Authorizer is stil not initialized");
    }

    String userName = "cdap";
    String ip = InetAddress.getLocalHost().getHostName();
    java.util.Set<String> userGroups = MiscUtil
      .getGroupsForRequestUser(userName);

    Date eventTime = new Date();
    String accessType = mapToRangerAccessType(action);

    boolean validationFailed = false;
    String validationStr = "";

    if (accessType == null) {
      if (MiscUtil.logErrorMessageByInterval(logger,
                                             "Unsupported access type. action=" + action)) {
        logger.fatal("Unsupported access type. entity=" + entity
                       + ", principal=" + principal + ", action=" + action);
      }
      validationFailed = true;
      validationStr += "Unsupported access type. action=" + action;
    }

    RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
    rangerRequest.setUser(userName);
    rangerRequest.setUserGroups(userGroups);
    rangerRequest.setClientIPAddress(ip);
    rangerRequest.setAccessTime(eventTime);

    RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
    rangerRequest.setResource(rangerResource);
    rangerRequest.setAccessType(accessType);
    rangerRequest.setAction(accessType);
    rangerRequest.setRequestData(entity.toString());

    if (entity.getEntity() == EntityType.NAMESPACE) {
      rangerResource.setValue(KEY_INSTANCE, ((InstanceId) entity).getInstance());
    } else {
      logger.fatal("Unsupported resourceType=" + entity.getEntity());
      validationFailed = true;
    }


    boolean returnValue = true;
    if (validationFailed) {
      MiscUtil.logErrorMessageByInterval(logger, validationStr + ", request=" + rangerRequest);
      returnValue = false;
    } else {
      try {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
        if (result == null) {
          logger.error("Ranger Plugin returned null. Returning false");
          returnValue = false;
        } else {
          returnValue = result.getIsAllowed();
        }
      } catch (Throwable t) {
        logger.error("Error while calling isAccessAllowed(). request="
                       + rangerRequest, t);
        throw t;
      } finally {
        if (logger.isDebugEnabled()) {
          logger.debug("rangerRequest=" + rangerRequest + ", return="
                         + returnValue);
        }
      }
    }
  }

  @Override
  public void grant(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public java.util.Set<Privilege> listPrivileges(Principal principal) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
    return Collections.emptySet();
  }

  @Override
  public void createRole(Role role) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void dropRole(Role role) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public java.util.Set<Role> listRoles(Principal principal) throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
    return Collections.emptySet();
  }

  @Override
  public java.util.Set<Role> listAllRoles() throws Exception {
    logger.error("Operation not supported by Ranger for CDAP");
    return Collections.emptySet();
  }

  @Override
  public void destroy() throws Exception {
    logger.info("destroy() called on authorizer.");
    try {
      if (rangerPlugin != null) {
        rangerPlugin.cleanup();
      }
    } catch (Throwable t) {
      logger.error("Error closing RangerPlugin.", t);
    }
  }
}
