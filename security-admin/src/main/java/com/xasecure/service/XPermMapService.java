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

 package com.xasecure.service;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.xasecure.common.SearchCriteria;
import com.xasecure.common.SearchField;

import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.xasecure.common.AppConstants;
import com.xasecure.common.view.VTrxLogAttr;
import com.xasecure.db.XADaoManager;
import com.xasecure.entity.*;
import com.xasecure.util.XAEnumUtil;
import com.xasecure.view.*;

@Service
@Scope("singleton")
public class XPermMapService extends XPermMapServiceBase<XXPermMap, VXPermMap> {

	@Autowired
	XGroupService xGroupService;
	
	@Autowired
	XUserService xUserService;
	
	@Autowired
	XAEnumUtil xaEnumUtil;

	@Autowired
	XADaoManager xADaoManager;

	static HashMap<String, VTrxLogAttr> trxLogAttrs = new HashMap<String, VTrxLogAttr>();
	static {
//		trxLogAttrs.put("groupId", new VTrxLogAttr("groupId", "Group Permission", false));
//		trxLogAttrs.put("userId", new VTrxLogAttr("userId", "User Permission", false));
		trxLogAttrs.put("permType", new VTrxLogAttr("permType", "Permission Type", true));
		trxLogAttrs.put("ipAddress", new VTrxLogAttr("ipAddress", "IP Address", false));
	}

	
	public XPermMapService() {
		searchFields.add(new SearchField("resourceId", "obj.resourceId",
				SearchField.DATA_TYPE.INTEGER, SearchField.SEARCH_TYPE.FULL));
		searchFields.add(new SearchField("permType", "obj.permType",
				SearchField.DATA_TYPE.INTEGER, SearchField.SEARCH_TYPE.FULL));
		searchFields.add(new SearchField("permFor", "obj.permFor",
				SearchField.DATA_TYPE.INTEGER, SearchField.SEARCH_TYPE.FULL));
		searchFields.add(new SearchField("userId", "obj.userId",
				SearchField.DATA_TYPE.INTEGER, SearchField.SEARCH_TYPE.FULL));
		searchFields.add(new SearchField("groupId", "obj.groupId",
				SearchField.DATA_TYPE.INTEGER, SearchField.SEARCH_TYPE.FULL));
	}

	@Override
	protected void validateForCreate(VXPermMap vObj) {
		// TODO Auto-generated method stub

	}

	@Override
	protected void validateForUpdate(VXPermMap vObj, XXPermMap mObj) {
		// TODO Auto-generated method stub

	}
	
	@Override
	public VXPermMap populateViewBean(XXPermMap xXPermMap){
		VXPermMap map = super.populateViewBean(xXPermMap);		
		if(map.getPermFor() == AppConstants.XA_PERM_FOR_GROUP) {
			String groupName = getGroupName(map.getGroupId());
			if(groupName != null){
				map.setGroupName(groupName);
			}
		} else if(map.getPermFor() == AppConstants.XA_PERM_FOR_USER) {
			String username = getUserName(map.getUserId());
			if(username != null){
				map.setUserName(username);
			}
		}
		return map;
	}
	
	@Override
	public VXPermMapList searchXPermMaps(SearchCriteria searchCriteria) {
		VXPermMapList vXPermMapList = super.searchXPermMaps(searchCriteria);
		if(vXPermMapList != null && vXPermMapList.getResultSize() != 0){
			for(VXPermMap vXPermMap : vXPermMapList.getVXPermMaps()){
				if(vXPermMap.getPermFor() == AppConstants.XA_PERM_FOR_GROUP) {
					String groupName = getGroupName(vXPermMap.getGroupId());
					vXPermMap.setGroupName(groupName);
				} else if(vXPermMap.getPermFor() == AppConstants.XA_PERM_FOR_USER) {
					String username = getUserName(vXPermMap.getUserId());
					vXPermMap.setUserName(username);
				}
			}
		}
		return vXPermMapList;
	}
	
	public String getGroupName(Long groupId){
		if(groupId!=null && groupId!=0){
		VXGroup vXGroup = xGroupService.readResource(groupId);
			return vXGroup.getName();
		}
		else
			return null;
	}
	
	public String getUserName(Long userId){
		if(userId!=null && userId!=0){
		VXUser vXUser = xUserService.readResource(userId);
			return vXUser.getName();
		}
		else
			return null;
	}

	public List<XXTrxLog> getTransactionLog(VXPermMap vXPermMap, String action){
		return getTransactionLog(vXPermMap, null, action);
	}
	
	public List<XXTrxLog> getTransactionLog(VXPermMap vObj, VXPermMap mObj, String action){
		if(vObj == null && (action == null || !action.equalsIgnoreCase("update"))){
			return null;
		}
		
		boolean isGroupPolicy = true;
		if(vObj.getGroupId() == null){
			isGroupPolicy = false;
		}
		
		Long groupId = null;
		Long userId = null;
		String groupName = null;
		String userName = null;
		
		if(isGroupPolicy){
			groupId = vObj.getGroupId();
			XXGroup xGroup = xADaoManager.getXXGroup().getById(groupId);
			groupName = xGroup.getName();
		} else {
			userId = vObj.getUserId();
			XXUser xUser = xADaoManager.getXXUser().getById(userId);
			userName = xUser.getName();
		}

		List<XXTrxLog> trxLogList = new ArrayList<XXTrxLog>();
		Field[] fields = vObj.getClass().getDeclaredFields();
		
		try {
			for(Field field : fields){
				field.setAccessible(true);
				String fieldName = field.getName();
				if(!trxLogAttrs.containsKey(fieldName)){
					continue;
//				int policyType = vObj.getIpAddress();
				/*if(policyType == AppConstants.ASSET_HDFS){
					String[] ignoredAttribs = {"ipAddress"};
					if(ArrayUtils.contains(ignoredAttribs, fieldName)){
						continue;
					}
				}*/	
//				} else {
//					if(isGroupPolicy){
//						if(fieldName.equalsIgnoreCase("userId")){
//							continue;
//						}
//					} else {
//						if (fieldName.equalsIgnoreCase("groupId")){
//							continue;
//						}
//					}
				}
				Long assetId = xADaoManager.getXXResource().getById(vObj.getResourceId()).getAssetId();
				int policyType = xADaoManager.getXXAsset().getById(assetId).getAssetType();
				if(policyType != AppConstants.ASSET_KNOX){
					if(fieldName.equals("ipAddress"))
						continue;
				} 
				
				VTrxLogAttr vTrxLogAttr = trxLogAttrs.get(fieldName);
				
				XXTrxLog xTrxLog = new XXTrxLog();
				xTrxLog.setAttributeName(vTrxLogAttr.getAttribUserFriendlyName());
			
				String value = null,prevValue = "";
				boolean isEnum = vTrxLogAttr.isEnum();
				if(isEnum){
					String enumName = XXPermMap.getEnumName(fieldName);
					int enumValue = field.get(vObj) == null ? 0 : Integer.parseInt(""+field.get(vObj));
					value = xaEnumUtil.getLabel(enumName, enumValue);
				} else {
					value = ""+field.get(vObj);
//					XXUser xUser = xADaoManager.getXXUser().getById(Long.parseLong(value));
//					value = xUser.getName();
					if(fieldName.equals("ipAddress") && action.equalsIgnoreCase("update")){
						prevValue = ""+field.get(mObj);
						value = value.equalsIgnoreCase("null") ? "" : value; 
					}
					else if(value == null || value.equalsIgnoreCase("null") || stringUtil.isEmpty(value)){
						continue;
					}
				}
				
				if(action.equalsIgnoreCase("create")){
					xTrxLog.setNewValue(value);
				} else if(action.equalsIgnoreCase("delete")){
					xTrxLog.setPreviousValue(value);
				} else if(action.equalsIgnoreCase("update")){
					// Not Changed.
					xTrxLog.setNewValue(value);
					xTrxLog.setPreviousValue(value);
					if(fieldName.equals("ipAddress")){
						xTrxLog.setPreviousValue(prevValue);
					}
				}
				
				xTrxLog.setAction(action);
				xTrxLog.setObjectClassType(AppConstants.CLASS_TYPE_XA_PERM_MAP);
				xTrxLog.setObjectId(vObj.getId());
				if(isGroupPolicy){
					xTrxLog.setParentObjectClassType(AppConstants.CLASS_TYPE_XA_GROUP);
					xTrxLog.setParentObjectId(groupId);
					xTrxLog.setParentObjectName(groupName);
				} else {
					xTrxLog.setParentObjectClassType(AppConstants.CLASS_TYPE_XA_USER);
					xTrxLog.setParentObjectId(userId);
					xTrxLog.setParentObjectName(userName);
				}
//				xTrxLog.setObjectName(objectName);
				trxLogList.add(xTrxLog);
				
			}
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			e.printStackTrace();
		}
		
		return trxLogList;
	}
	
	@Override
	protected XXPermMap mapViewToEntityBean(VXPermMap vObj, XXPermMap mObj, int OPERATION_CONTEXT) {
		super.mapViewToEntityBean(vObj, mObj, OPERATION_CONTEXT);
		if(vObj!=null && mObj!=null){
			XXPortalUser xXPortalUser=null;
			if(mObj.getAddedByUserId()==null || mObj.getAddedByUserId()==0){
				if(!stringUtil.isEmpty(vObj.getOwner())){
					xXPortalUser=xADaoManager.getXXPortalUser().findByLoginId(vObj.getOwner());	
					if(xXPortalUser!=null){
						mObj.setAddedByUserId(xXPortalUser.getId());
					}
				}
			}
			if(mObj.getUpdatedByUserId()==null || mObj.getUpdatedByUserId()==0){
				if(!stringUtil.isEmpty(vObj.getUpdatedBy())){
					xXPortalUser= xADaoManager.getXXPortalUser().findByLoginId(vObj.getUpdatedBy());			
					if(xXPortalUser!=null){
						mObj.setUpdatedByUserId(xXPortalUser.getId());
					}		
				}
			}
		}
		return mObj;
	}

	@Override
	protected VXPermMap mapEntityToViewBean(VXPermMap vObj, XXPermMap mObj) {
		super.mapEntityToViewBean(vObj, mObj);
		if(mObj!=null && vObj!=null){
			XXPortalUser xXPortalUser=null;
			if(stringUtil.isEmpty(vObj.getOwner())){
				xXPortalUser= xADaoManager.getXXPortalUser().getById(mObj.getAddedByUserId());	
				if(xXPortalUser!=null){
					vObj.setOwner(xXPortalUser.getLoginId());
				}
			}
			if(stringUtil.isEmpty(vObj.getUpdatedBy())){
				xXPortalUser= xADaoManager.getXXPortalUser().getById(mObj.getUpdatedByUserId());		
				if(xXPortalUser!=null){
					vObj.setUpdatedBy(xXPortalUser.getLoginId());
				}
			}
		}
		return vObj;
	}
}