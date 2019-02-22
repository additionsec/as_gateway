// Copyright 2019 J Forristal LLC
// Copyright 2016 Addition Security Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.additionsecurity;

import com.additionsecurity.cti.AddsecCti;
import com.additionsecurity.cti.AddsecCti.Report;
import com.additionsecurity.cti.AddsecCti.Sighting;
import com.additionsecurity.cti.AddsecCti.ObservationData;
import com.additionsecurity.ICTIInput.ICTIInputException;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Properties;
import java.util.HashMap;
import java.util.List;
import java.io.InputStream;
import java.nio.charset.Charset;

import javax.xml.bind.DatatypeConverter;

class InputCTIProtobuf implements ICTIInput {

	private static final String DESC = "AddSec Protobuf";

	// field limits
	private static final int MAX_ORG = 32;
	private static final int MAX_SYS1 = 32;
	private static final int MAX_SYS2 = 256;
	private static final int MAX_ACCT1 = 32;
	private static final int MAX_ACCT2 = 256;
	private static final int MAX_APP = 256;
	private static final int MAX_DATA_SIZE = 2048;
	private static final int MAX_DATA_COUNT = 8; // MUST BE <= 9, or adjust all the transforms

	private static boolean _coalesce;
	private static byte[] _orgLimit;
	private static byte[] _orgLearned;
	private static String _orgLimitStr;

	public InputCTIProtobuf(Properties prop)  throws Exception
	{
		String v = prop.getProperty("input.coalesce_disable","");
		if( "true".equals(v) ) _coalesce = false;
		else _coalesce = true;

		v = prop.getProperty("input.limit_org",null);
		if( v == null ) _orgLimit = null;
		else {
			// ORG is SHA1, aka 20 bytes, 40 hex chars
			if( v.length() != 40 )
				throw new Exception("input.limit_org must be 40 hex chars");
			_orgLimit = DatatypeConverter.parseHexBinary(v);
			if( _orgLimit.length != 20 )
				throw new Exception("input.limit_org must be 40 hex chars");
			_orgLimitStr = v;
			_orgLearned = _orgLimit;
		}
	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC);
		if( _orgLimit != null ) sb.append("; limit_org=").append(_orgLimitStr);
		return sb.toString();
	}

	public byte[] learnedOrgId()
	{
		return _orgLearned;
	}

	//public CTIItem[] process(byte[] ip, long ts, byte[] data) throws ICTIInputException
	public CTIItem[] process(byte[] ip, long ts, InputStream data) throws ICTIInputException
	{
		Report report;

		try {
			report = Report.parseFrom(data);
		} catch(Exception e){
			// Bad data will cause malformed parsing results; it's
			// somewhat expected.
			//throw new ICTIInputException("parsing", e);
			if( App.DEBUG ) App.err(e);
			return null;
		}

		// check for org limit
		if( _orgLimit != null ){
			if( !report.hasOrganizationId() ) return null;
			final byte[] org = report.getOrganizationId().toByteArray();
			if( org.length != _orgLimit.length ) return null;
			if( !Arrays.equals(org, _orgLimit) ) return null;
		}

		final int obsz = report.getSightingsList().size();
		if( obsz == 0 ) return null; // no observations

		//ArrayList<CTIItem> results = new ArrayList<CTIItem>( report.getObservationsList().size() );
		CTIItem results[] = new CTIItem[ obsz ];

		results[0] = new CTIItem();

		// Common report items
		results[0].setRecvTs(ts).setRecvIp(ip);
		if(report.hasOrganizationId()){ 
			results[0].setOrgId(report.getOrganizationId().toByteArray()); 
			if( results[0]._org.length > MAX_ORG ) return null;
			if( _orgLearned == null ) _orgLearned = results[0]._org;
		}
		if(report.hasSystemId()){
			results[0].setSysId(report.getSystemId().toByteArray());
			if( results[0]._sys.length > MAX_SYS1 ) return null;
		}
		if(report.hasSystemIdSecondary()){
			results[0].setSysId2(report.getSystemIdSecondary().toByteArray());
			if( results[0]._sys2.length > MAX_SYS2 ) return null;
		}
		if(report.hasApplicationId()){
			results[0].setAppId(report.getApplicationId().toByteArray());
			if( results[0]._app.length > MAX_APP ) return null;
		}
		if(report.hasUserId()){ 
			results[0].setUserId(report.getUserId().toByteArray());
			if( results[0]._user.length > MAX_ACCT1 ) return null;
		}
		if(report.hasUserIdSecondary()){ 
			results[0].setUserId2(report.getUserIdSecondary().toByteArray());
			if( results[0]._user2.length > MAX_ACCT2 ) return null;
		}
		//if(report.hasSystemType()) results[0].setSysType(report.getSystemType().getNumber());
		if(report.hasSystemType()) results[0].setSysType(report.getSystemType());


		long time_base = 0;
		if(report.hasTimeBase()) time_base = report.getTimeBase();

		HashMap<Long,Long> cache = new HashMap<Long,Long>();

		//for( Observation ob : report.getObservationsList() ){
		List<Sighting> obl = report.getSightingsList();
		for( int i=0; i<obsz; i++ ){
			Sighting ob = obl.get(i);

			long ts_ = 0;
			if( ob.hasTimestamp() ) ts_ = ob.getTimestamp();
			else if( ob.hasTimeDelta() ) ts_ = ob.getTimeDelta() + time_base;

			// Check for coalesce
			long subtest_ = 0;
			if( ob.hasTestSubId() ) subtest_ = ob.getTestSubId();
			if( _coalesce && subtest_ > 0 && ob.hasTestId() ){
				final long cacheval = (ob.getTestId() << 32) | subtest_;
				if( cache.containsKey(cacheval) ){
					final long exp = cache.get(cacheval);
					if( ts_ < exp ){
						// duplicate and within expire window, so skip
						continue;
					}
				}

				// add this item to the cache
				final long new_exp = ts_ + (60 * 5); // 5 minutes
				cache.put( cacheval, new_exp );
			}

			if( i > 0 ) results[i] = results[0].cloneBase();

			CTIItem item_ = results[i];

			/*
			item_.setRecvTs(ts).setRecvIp(ip);
			if(report.hasOrganizationId()) item_.setOrgId(report.getOrganizationId().toByteArray());
			if(report.hasSystemId()) item_.setSysId(report.getSystemId().toByteArray());
			if(report.hasSystemIdSecondary()) item_.setSysId2(report.getSystemIdSecondary().toByteArray());
			if(report.hasSystemType()) item_.setSysType(report.getSystemType().getNumber());
			if(report.hasApplicationId()) item_.setAppId(report.getApplicationId().toByteArray());
			if(report.hasUserId()) item_.setUserId(report.getUserId().toByteArray());
			if(report.hasUserIdSecondary()) item_.setUserId2(report.getUserIdSecondary().toByteArray());
			*/

			CTIItem.Ob ob_ = new CTIItem.Ob();
			//ob_.setType(ob.getObservationType().getNumber()).setTs(ts_);
			ob_.setType(ob.getSightingType()).setTs(ts_);

			//if(ob.hasConfidence()) ob_.setConf(ob.getConfidence().getNumber());
			if(ob.hasConfidence()) ob_.setConf(ob.getConfidence());
			//if(ob.hasImpact()) ob_.setImp(ob.getImpact().getNumber());
			//if(ob.hasImpact()) ob_.setImp(ob.getImpact());
			if(ob.hasTestId()) ob_.setTest(ob.getTestId());
			if(ob.hasTestSubId()) ob_.setTest2(ob.getTestSubId());

			for( ObservationData obd : ob.getDatasList() ){
				CTIItem.ObData obd_;
				if( obd.hasData() ){
					final byte[] d = obd.getData().toByteArray();
					if( d.length <= MAX_DATA_SIZE ){
						//obd_ = new CTIItem.ObData(obd.getDataType().getNumber(), 
						obd_ = new CTIItem.ObData(obd.getDataType(), 
							obd.getData().toByteArray());
						ob_.addData(obd_);
					}
				}
				else if( obd.hasNum() ){
					//obd_ = new CTIItem.ObData(obd.getDataType().getNumber(), obd.getNum());
					obd_ = new CTIItem.ObData(obd.getDataType(), obd.getNum());
					ob_.addData(obd_);
				}

				// Max the number of data items per observation
				if( ob_._datas.size() >= MAX_DATA_COUNT ) break;
			}

			item_.setObservation(ob_);
			//results.add(item_);
		}

		//return results.toArray( new CTIItem[results.size()] );
		return results;
	}
}

