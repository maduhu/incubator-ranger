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

package org.apache.ranger.audit.destination;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.util.*;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.provider.MiscUtil;

/**
 * This class write the logs to local file
 */
public class HDFSAuditDestination extends AuditDestination {
	private static final Log logger = LogFactory
			.getLog(HDFSAuditDestination.class);

	public static final String PROP_HDFS_DIR = "dir";
	public static final String PROP_HDFS_SUBDIR = "subdir";
	public static final String PROP_HDFS_FILE_NAME_FORMAT = "filename.format";
	public static final String PROP_HDFS_ROLLOVER = "file.rollover.sec";

	String baseFolder = null;
	String fileFormat = null;
	int fileRolloverSec = 24 * 60 * 60; // In seconds
	private String logFileNameFormat;

	boolean initDone = false;

	private String logFolder;
	PrintWriter logWriter = null;

	private Date fileCreateTime = null;

	private String currentFileName;

	private boolean isStopped = false;

	@Override
	public void init(Properties prop, String propPrefix) {
		super.init(prop, propPrefix);

		// Initialize properties for this class
		// Initial folder and file properties
		String logFolderProp = MiscUtil.getStringProperty(props, propPrefix
				+ "." + PROP_HDFS_DIR);
		if (logFolderProp == null || logFolderProp.isEmpty()) {
			logger.fatal("File destination folder is not configured. Please set "
					+ propPrefix + "." + PROP_HDFS_DIR + ". name=" + getName());
			return;
		}

		String logSubFolder = MiscUtil.getStringProperty(props, propPrefix
				+ "." + PROP_HDFS_SUBDIR);
		if (logSubFolder == null || logSubFolder.isEmpty()) {
			logSubFolder = "%app-type%/%time:yyyyMMdd%";
		}

		logFileNameFormat = MiscUtil.getStringProperty(props, propPrefix + "."
				+ PROP_HDFS_FILE_NAME_FORMAT);
		fileRolloverSec = MiscUtil.getIntProperty(props, propPrefix + "."
				+ PROP_HDFS_ROLLOVER, fileRolloverSec);

		if (logFileNameFormat == null || logFileNameFormat.isEmpty()) {
			logFileNameFormat = "%app-type%_ranger_audit_%hostname%" + ".log";
		}

		logFolder = logFolderProp + "/" + logSubFolder;
		logger.info("logFolder=" + logFolder + ", destName=" + getName());
		logger.info("logFileNameFormat=" + logFileNameFormat + ", destName="
				+ getName());
		logger.info("config=" + configProps.toString());
		initDone = true;
	}

	@Override
	synchronized public boolean logJSON(Collection<String> events) {
		logStatusIfRequired();
		addTotalCount(events.size());

		if (!initDone) {
			addDeferredCount(events.size());
			return false;
		}
		if (isStopped) {
			addDeferredCount(events.size());
			logError("log() called after stop was requested. name=" + getName());
			return false;
		}

		try {
			if (logger.isDebugEnabled()) {
				logger.debug("UGI=" + MiscUtil.getUGILoginUser()
						+ ". Will write to HDFS file=" + currentFileName);
			}
			PrintWriter out = getLogFileStream();
			for (String event : events) {
				out.println(event);
			}
			// flush and check the stream for errors
			if (out.checkError()) {
				// In theory, this count may NOT be accurate as part of the messages may have been successfully written.
				// However, in practice, since client does buffering, either all of none would succeed.
				addDeferredCount(events.size());
				out.close();
				logWriter = null;
				return false;
			}
		} catch (Throwable t) {
			addDeferredCount(events.size());
			logError("Error writing to log file.", t);
			return false;
		}
		addSuccessCount(events.size());
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.ranger.audit.provider.AuditProvider#log(java.util.Collection)
	 */
	@Override
	public boolean log(Collection<AuditEventBase> events) {
		if (isStopped) {
			logStatusIfRequired();
			addTotalCount(events.size());
			addDeferredCount(events.size());
			logError("log() called after stop was requested. name=" + getName());
			return false;
		}
		List<String> jsonList = new ArrayList<String>();
		for (AuditEventBase event : events) {
			try {
				jsonList.add(MiscUtil.stringify(event));
			} catch (Throwable t) {
				logger.error("Error converting to JSON. event=" + event);
				addTotalCount(1);
				addFailedCount(1);
				logFailedEvent(event);
			}
		}
		return logJSON(jsonList);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.ranger.audit.provider.AuditProvider#start()
	 */
	@Override
	public void start() {
		// Nothing to do here. We will open the file when the first log request
		// comes
	}

	@Override
	synchronized public void stop() {
		isStopped = true;
		if (logWriter != null) {
			try {
				logWriter.flush();
				logWriter.close();
			} catch (Throwable t) {
				logger.error("Error on closing log writter. Exception will be ignored. name="
						+ getName() + ", fileName=" + currentFileName);
			}
			logWriter = null;
		}
		logStatus();
	}

	// Helper methods in this class
	synchronized private PrintWriter getLogFileStream() throws Throwable {
		closeFileIfNeeded();

		// Either there are no open log file or the previous one has been rolled
		// over
		if (logWriter == null) {
			Date currentTime = new Date();
			// Create a new file
			String fileName = MiscUtil.replaceTokens(logFileNameFormat,
					currentTime.getTime());
			String parentFolder = MiscUtil.replaceTokens(logFolder,
					currentTime.getTime());
			Configuration conf = createConfiguration();

			String fullPath = parentFolder + Path.SEPARATOR + fileName;
			String defaultPath = fullPath;
			URI uri = URI.create(fullPath);
			FileSystem fileSystem = FileSystem.get(uri, conf);

			Path hdfPath = new Path(fullPath);
			logger.info("Checking whether log file exists. hdfPath=" + fullPath + ", UGI=" + MiscUtil.getUGILoginUser());
			int i = 0;
			while (fileSystem.exists(hdfPath)) {
				i++;
				int lastDot = defaultPath.lastIndexOf('.');
				String baseName = defaultPath.substring(0, lastDot);
				String extension = defaultPath.substring(lastDot);
				fullPath = baseName + "." + i + extension;
				hdfPath = new Path(fullPath);
				logger.info("Checking whether log file exists. hdfPath="
						+ fullPath);
			}
			logger.info("Log file doesn't exists. Will create and use it. hdfPath="
					+ fullPath);
			// Create parent folders
			createParents(hdfPath, fileSystem);

			// Create the file to write
			logger.info("Creating new log file. hdfPath=" + fullPath);
			FSDataOutputStream ostream = fileSystem.create(hdfPath);
			logWriter = new PrintWriter(ostream);
			fileCreateTime = new Date();
			currentFileName = fullPath;
		}
		return logWriter;
	}

	Configuration createConfiguration() {
		Configuration conf = new Configuration();
		for (Map.Entry<String, String> entry : configProps.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			// for ease of install config file may contain properties with empty value, skip those
			if (StringUtils.isNotEmpty(value)) {
				conf.set(key, value);
			}
			logger.info("Adding property to HDFS config: " + key + " => " + value);
		}

		logger.info("Returning HDFS Filesystem Config: " + conf.toString());
		return conf;
	}

	private void createParents(Path pathLogfile, FileSystem fileSystem)
			throws Throwable {
		logger.info("Creating parent folder for " + pathLogfile);
		Path parentPath = pathLogfile != null ? pathLogfile.getParent() : null;

		if (parentPath != null && fileSystem != null
				&& !fileSystem.exists(parentPath)) {
			fileSystem.mkdirs(parentPath);
		}
	}

	private void closeFileIfNeeded() throws FileNotFoundException, IOException {
		if (logWriter == null) {
			return;
		}
		// TODO: Close the file on absolute time. Currently it is implemented as
		// relative time
		if (System.currentTimeMillis() - fileCreateTime.getTime() > fileRolloverSec * 1000) {
			logger.info("Closing file. Rolling over. name=" + getName()
					+ ", fileName=" + currentFileName);
			try {
				logWriter.flush();
				logWriter.close();
			} catch (Throwable t) {
				logger.error("Error on closing log writter. Exception will be ignored. name="
						+ getName() + ", fileName=" + currentFileName);
			}

			logWriter = null;
			currentFileName = null;
		}
	}

}
