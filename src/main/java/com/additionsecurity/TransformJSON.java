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

import com.additionsecurity.CTIItem;
import com.additionsecurity.CTIItem.Ob;
import com.additionsecurity.CTIItem.ObData;
import com.additionsecurity.ICTITransform;
import com.additionsecurity.ICTITransform.ICTITransformException;
import com.additionsecurity.Utils;
import com.additionsecurity.Decode;

import io.vertx.core.json.*;

import java.lang.StringBuilder;
import java.util.ArrayList;
import java.util.Properties;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.nio.charset.Charset;

public class TransformJSON implements ICTITransform {

	private static final String VER = "1.0";
	private static final String DESC = "JSON";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private boolean _includeOrg = false;
	private boolean _includeTs = false;
	private boolean _includeTitle = false;
	private boolean _accountName2String = false;
	private boolean _resource2String = false;
	private String _hostname = "";

	public void reconfigure(Properties prop)
	{
		// Local configuration
		String rts = prop.getProperty("transform._recvtimestamp","");
		if( "include".equals(rts) ) _includeTs = true;
		else _includeTs = false;

		String v = prop.getProperty("transform.include_title","");
		if( "true".equals(v) ) _includeTitle = true;
		else _includeTitle = false;

		v = prop.getProperty("transform.accountName2_string","");
		if( "true".equals(v) ) _accountName2String = true;
		else _accountName2String = false;

		v = prop.getProperty("transform.include_organizationId","");
		if( "true".equals(v) ) _includeOrg = true;
		else _includeOrg = false;

		v = prop.getProperty("transform.systemId2_string","");
		if( "true".equals(v) ) _resource2String = true;
		else _resource2String = false;

		_hostname = " " + prop.getProperty("_hostname","asgw") + " ";
	}

	public TransformJSON(Properties prop)
	{
		reconfigure(prop);
	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC);
		if( _includeTs ) sb.append("; timestamp=true");
		if( _includeTitle ) sb.append("; title=true");
		if( _includeOrg ) sb.append("; org=true");
		if( _accountName2String ) sb.append("; accountName2String=true");
		return sb.toString();
	}

	public String header()
	{
		return null;
	}

	public boolean isMultiLine()
	{
		return true;
	}

	public String extension()
	{
		return "json";
	}

        private static DateTimeFormatter _formatter = DateTimeFormatter.ofPattern("MMM dd yyyy HH:mm:ss")
                .withZone(ZoneId.systemDefault());

	private String _nowString;
	public void nowTick(long ts)
	{
		_nowString = _formatter.format(Instant.ofEpochSecond(ts));
	}

	private static String strTs(long ts)
	{
		final Instant instant = Instant.ofEpochSecond(ts);
		return DateTimeFormatter.ISO_INSTANT.format(instant);
	}

	public byte[] dataToByteString(byte[] data) throws ICTITransformException
	{
		return data;
		//return dataToString(data).getBytes(_UTF8);
	}

        public String dataToString(byte[] data) throws ICTITransformException
        {
		try {
			return new String( data, _UTF8 );

		} catch(Exception e){
			// Something went awry, just return hex encoded data
			return "0x" + Utils.hex(data);
		}
        }

	public Object groupObject(CTIItem items[]) throws ICTITransformException
	{
		return null;
	}

	public byte[] transform(CTIItem item, Object group) throws ICTITransformException
	{
	  try {

		JsonObject js = new JsonObject();
		js.put("id", item._ob._test);

		if( _includeTitle ){
			js.put("title", Decode.title(item._ob._test,item._ob._test2));
		}

		if( item._ob._test2 > 0 ) js.put("subId", item._ob._test2);

		js.put("timestamp", strTs(item._ob._ts));

		if( item._ob._type > 0 ) js.put("category", Decode.observationType(item._ob._type));
		js.put("recvIp", Decode.ipv4ToString(item._recvip));

		if( _includeOrg ) js.put("org", Utils.hex(item._org, true) );

		if( item._ob._imp > 0 ) js.put("impact",Decode.impact(item._ob._imp));
		if( item._ob._conf > 0 ) js.put("confidence",Decode.confidence(item._ob._conf));

		if( item._user != null && item._user.length > 0 )
			js.put("accountId",Utils.hex(item._user, true));
		if( item._user2 != null && item._user2.length > 0 ){
			if( _accountName2String )
				js.put("accountId2",item._user2);
				//js.put("accountId2",new String(item._user2, _UTF8));
			else
				js.put("accountId2",Utils.hex(item._user2, true));
		}

		if( item._sysType > 0 )
			js.put("systemType",Decode.systemType(item._sysType));
		if( item._sys != null && item._sys.length > 0 )
			js.put("systemId",Utils.hex(item._sys, true));
		if( item._sys2 != null && item._sys2.length > 0 ){
			if( _resource2String )
				js.put("systemId2",new String(item._sys2, _UTF8));
			else
				js.put("systemId2",Utils.hex(item._sys2, true));
		}

		if( item._app != null && item._app.length > 0 )
			js.put("application",item._app);
			//js.put("application",new String(item._app, _UTF8));

		JsonObject js2 = new JsonObject();
		js.put("observableData", js2);

		final HashSet<String> seen = new HashSet<String>();
		for( CTIItem.ObData obd : item._ob._datas ){

			// Performant way of lowercasing the first character
			char c[] = Decode.dataType(obd._type).toCharArray();
			c[0] += 32;
			String dtype = new String(c);

			// Append _2, _3 for subsequent same key names (since JSON doesn't allow
			// dupes)
			if( seen.contains(dtype) ){
				int i = 2;
				String k;
				while(true){
					k = dtype + String.valueOf(i);
					if( !seen.contains(k) ) break;
					i = i + 1;
				}
				dtype = k;
			}
			seen.add(dtype);

			String dval;
			if( obd._data != null )
				js2.put(dtype, Decode.dataToByteString(obd._type, obd._data, this));
			else
				js2.put(dtype, obd._num);
		}

		if( _includeTs ){
			StringBuilder sb = new StringBuilder();
			sb.append(_formatter.format(Instant.now()));
			sb.append(_hostname);
			sb.append( js.toString() );
			return sb.toString().getBytes(_UTF8);
		}

		return js.toString().getBytes(_UTF8);

	  } catch(Exception e){
		throw new ICTITransformException("transform", e);
	  }
	}
}
