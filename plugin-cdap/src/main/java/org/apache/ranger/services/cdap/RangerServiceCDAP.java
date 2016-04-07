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

package org.apache.ranger.services.cdap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.model.RangerService;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.service.RangerBaseService;
import org.apache.ranger.plugin.service.ResourceLookupContext;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class RangerServiceCDAP extends RangerBaseService {
  private static final Log LOG = LogFactory.getLog(RangerServiceCDAP.class);

  public RangerServiceCDAP() {
    super();
  }

  @Override
  public void init(RangerServiceDef serviceDef, RangerService service) {
    super.init(serviceDef, service);
  }

  @Override
  public HashMap<String, Object> validateConfig() throws Exception {
    HashMap<String, Object> ret = new HashMap<String, Object>();

    if (LOG.isDebugEnabled()) {
      LOG.debug("==> RangerServiceKafka.validateConfig(" + serviceName + ")");
    }

    if (configs != null) {
      try {
        return new HashMap<>();
      } catch (Exception e) {
        LOG.error("<== RangerServiceKafka.validateConfig Error:" + e);
        throw e;
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerServiceKafka.validateConfig(" + serviceName + "): ret=" + ret);
    }

    return ret;
  }

  @Override
  public List<String> lookupResource(ResourceLookupContext context) throws Exception {
    List<String> ret = null;

    if (LOG.isDebugEnabled()) {
      LOG.debug("==> RangerServiceKafka.lookupResource(" + serviceName + ")");
    }

    if (configs != null) {
      return new LinkedList<>();
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerServiceKafka.lookupResource(" + serviceName + "): ret=" + ret);
    }

    return ret;
  }
}
