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

import java.lang.StringBuilder;
import java.util.ArrayList;
import java.util.Properties;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.nio.charset.Charset;

public class TransformLEEF implements ICTITransform {

	private static final String VER = App.VER;
	private static final String DESC = "LEEF";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private static final String LEEFHEADER = "LEEF|1.0|AdditionSecurity|ASGW|"+VER+"|";
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

	public TransformLEEF(Properties prop)
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
		return false;
	}

	public String extension()
	{
		return "leef";
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
		return _formatter.format(instant);
	}

	public byte[] dataToByteString(byte[] data) throws ICTITransformException
	{
		return dataToString(data).getBytes();
	}

        public String dataToString(byte[] data) throws ICTITransformException
        {
		StringBuilder sb = null;
		int i;
		int offset = 0;
		byte[] ba = new byte[1];
		
		try {
			for( i=offset; i<data.length; i++){

				// General characters that don't need escaping
				// LEEF: doesn't like pipe (124), caret (94), and tab (9)
				if( data[i] >= 32 && data[i] <= 127 && data[i] != 124 
					&& data[i] != 94) continue;

				// Something needs escaping

				// allocate an SB if we don't have it
				if( sb == null ) sb = new StringBuilder();

				// Copy everything up to now to the sb
				if( (i-offset) > 0 )
					sb.append( new String(data, offset, (i-offset), _UTF8) );

				// Figure out the escape char
				// NOTE: just hex encode everything, there is no escape char
				sb.append("\\x");
				ba[0] = data[i];
				sb.append( Utils.hex(ba) );

				offset = i + 1;
			}

			if( sb == null ){
				// Nothing needed escaping, it's a clean string
				return new String(data, _UTF8);
			}

			if( (data.length - offset) > 0 ){
				// Need to push the trailer into the sb
				sb.append( new String(data, offset, (data.length-offset), _UTF8) );
			}

			return sb.toString();

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
		StringBuilder sb = new StringBuilder();

		if( _includeTs ){
			//sb.append(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
			//sb.append(_formatter.format(Instant.now()));
			sb.append( _nowString );
			sb.append(_hostname);
		}
		sb.append(LEEFHEADER).append(item._ob._test).append("|");

		sb.append("devTimeFormat=MMM dd yyyy HH:mm:ss\tdevTime=");
		sb.append( strTs(item._ob._ts) );
		if( item._ob._type > 0 ) sb.append("\tcat=").append(Decode.observationType(item._ob._type));
		sb.append("\tsrc=").append(Decode.ipv4ToString(item._recvip));

		if( _includeOrg ) sb.append("\torg=").append(Utils.hex(item._org, true));

		if( item._ob._imp > 0 ) sb.append("\tsev=").append(item._ob._imp);
		if( item._ob._conf > 0 ) sb.append("\tconfidence=")
			.append(Decode.confidence(item._ob._conf));

		if( _includeTitle ){
			sb.append("\ttitle=").append(Decode.title(item._ob._test,item._ob._test2));
		}

		if( item._user != null && item._user.length > 0 )
			sb.append("\taccountName=").append(Utils.hex(item._user, true));
		if( item._user2 != null && item._user2.length > 0 ){
			if( _accountName2String )
				sb.append("\taccountName2=").append(new String(item._user2, "UTF-8"));
			else
				sb.append("\taccountName2=").append(Utils.hex(item._user2, true));
		}

		if( item._sysType > 0 )
			sb.append("\tresourceType=").append(Decode.systemType(item._sysType));
		if( item._sys != null && item._sys.length > 0 )
			sb.append("\tresource=").append(Utils.hex(item._sys, true));
		if( item._sys2 != null && item._sys2.length > 0 ){
			if( _resource2String )
				sb.append("\tresource2=").append(new String(item._sys2, "UTF-8"));
			else
				sb.append("\tresource2=").append(Utils.hex(item._sys2, true));
		}

		if( item._app != null && item._app.length > 0 )
			sb.append("\tapplication=").append(new String(item._app, "UTF-8"));

		if( item._ob._test2 > 0 )
			sb.append("\tevent2=").append(item._ob._test2);

		final HashSet<String> seen = new HashSet<String>();
		for( CTIItem.ObData obd : item._ob._datas ){

			// Performant way of lowercasing the first character
			char c[] = Decode.dataType(obd._type).toCharArray();
			c[0] += 32;
			String dtype = new String(c);

			// Append _2, _3 for subsequent same key names (since LEEF doesn't allow
			// dupes)
			if( seen.contains(dtype) ){
				int i = 2;
				String k;
				while(true){
					k = dtype + "_" + String.valueOf(i);
					if( !seen.contains(k) ) break;
					i = i + 1;
				}
				dtype = k;
			}
			seen.add(dtype);

			String dval;
			if( obd._data != null )
				dval = Decode.dataToString(obd._type, obd._data, this);
			else
				dval = Decode.dataToString(obd._type, obd._num);
			sb.append("\t").append(dtype).append("=").append(dval);
		}

		return sb.toString().getBytes(_UTF8);

	  } catch(Exception e){
		throw new ICTITransformException("transform", e);
	  }
	}
}
