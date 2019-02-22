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

public class TransformCEF implements ICTITransform {

	private static final String VER = App.VER;
	private static final String DESC = "CEF";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private static final String CEFHEADER = "CEF:0|AdditionSecurity|ASGW|"+VER+"|";
	private boolean _includeTs = false;
	private boolean _includeTitle = false;
	private boolean _includeOrg = false;
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

		v = prop.getProperty("transform.include_organizationId","");
		if( "true".equals(v) ) _includeOrg = true;
		else _includeOrg = false;

		v = prop.getProperty("transform.accountName2_string","");
		if( "true".equals(v) ) _accountName2String = true;
		else _accountName2String = false;

		v = prop.getProperty("transform.systemId2_string","");
		if( "true".equals(v) ) _resource2String = true;
		else _resource2String = false;

		_hostname = " " + prop.getProperty("_hostname","asgw") + " ";
	}

	public TransformCEF(Properties prop)
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
		return "cef";
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
		return dataToString(data).getBytes(_UTF8);
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
				// CEF: doesn't like pipe (124), backslash (92), and equals (61)
				if( data[i] >= 32 && data[i] <= 127 && data[i] != 124 
					&& data[i] != 92 && data[i] != 61 ) continue;

				// Something needs escaping

				// allocate an SB if we don't have it
				if( sb == null ) sb = new StringBuilder();

				// Copy everything up to now to the sb
				if( (i-offset) > 0 )
					sb.append( new String(data, offset, (i-offset), _UTF8) );

				// Figure out the escape char
				if( data[i] == 124 || data[i] == 92 || data[i] == 61 ){
					sb.append('\\');
					sb.append((char)data[i]);
				} else {
					sb.append("\\x");
					ba[0] = data[i];
					sb.append( Utils.hex(ba) );
				}

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

	private static char _severity(int impact)
	{
		// Convert AddSec CTI impact levels to normalized CEF severity levels
		// Addsec: 0=Unknown, 1=None, 2=Minor, 3=Moderate, 4=Major
		// CEF: 0-3=Low, 4-6=Medium, 7-8=High, 9-10=Very High
		if( impact == 4 ) return '8'; // Major => High
		if( impact == 3 ) return '5'; // Moderate => Medium
		if( impact == 2 ) return '3'; // Minor => Low
		return '0'; // None/Unknown
	}

	public byte[] transform(CTIItem item, Object group) throws ICTITransformException
	{
	  try {
		StringBuilder sb = new StringBuilder();

		int cs_ctr = 1;
		int cn_ctr = 1;

		if( _includeTs ){
			//sb.append(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
			//sb.append(_formatter.format(Instant.now()));
			sb.append(_nowString);
			sb.append(_hostname);
		}
		sb.append(CEFHEADER).append(item._ob._test).append("|");
		sb.append(Decode.title(item._ob._test, item._ob._test2));
		sb.append("|").append(_severity(item._ob._imp)).append("|");

		// Extensions after this point
		sb.append("start=").append( strTs(item._ob._ts) );
		sb.append(" dvc=").append(Decode.ipv4ToString(item._recvip));

		if( _includeOrg ){
			sb.append(" cs1Label=org cs1=");
			sb.append(Utils.hex(item._org, true));
			cs_ctr++;
		}

		//sb.append("\tcat=").append(Decode.observationType(item._ob._type));
		//if( item._ob._conf > 0 ) sb.append("\tconfidence=")
		//	.append(Decode.confidence(item._ob._conf));

		if( item._user != null && item._user.length > 0 )
			sb.append(" suser=").append(Utils.hex(item._user, true));
		if( item._user2 != null && item._user2.length > 0 ){
			sb.append(" cs");
			sb.append(cs_ctr);
			sb.append("Label=suser2 cs");
			sb.append(cs_ctr);
			sb.append("=");
			cs_ctr++;
			if( _accountName2String )
				sb.append(new String(item._user2, "UTF-8"));
			else
				sb.append(Utils.hex(item._user2, true));
		}

		if( item._sysType > 0 ){
			sb.append(" cs");
			sb.append(cs_ctr);
			sb.append("Label=deviceType cs");
			sb.append(cs_ctr);
			sb.append("=");
			cs_ctr++;
			sb.append(Decode.systemType(item._sysType));
		}

		if( item._sys != null && item._sys.length > 0 )
			sb.append(" deviceExternalId=").append(Utils.hex(item._sys, true));
		if( item._sys2 != null && item._sys2.length > 0 ){
			sb.append(" cs");
			sb.append(cs_ctr);
			sb.append("Label=deviceExternalId2 cs");
			sb.append(cs_ctr);
			sb.append("=");
			cs_ctr++;
			if( _resource2String )
				sb.append(new String(item._sys2, "UTF-8"));
			else
				sb.append(Utils.hex(item._sys2, true));
		}

		if( item._app != null && item._app.length > 0 )
			sb.append(" deviceProcessName=").append(new String(item._app, "UTF-8"));

		if( item._ob._test2 > 0 ) {
			sb.append(" cn");
			sb.append(cn_ctr);
			sb.append("Label=eventSubId cn");
			sb.append(cn_ctr);
			sb.append("=");
			cn_ctr++;
			sb.append(item._ob._test2);
		}

		final HashSet<String> seen = new HashSet<String>();
		for( CTIItem.ObData obd : item._ob._datas ){

			// Performant way of lowercasing the first character
			char c[] = Decode.dataType(obd._type).toCharArray();
			c[0] += 32;
			String dtype = new String(c);

			if( obd._data != null ){
				sb.append(" cs");
				sb.append(cs_ctr);
				sb.append("Label=");
				sb.append(dtype);
				sb.append(" cs");
				sb.append(cs_ctr);
				sb.append("=");
				cs_ctr++;
				String dval = Decode.dataToString(obd._type, obd._data, this);
				sb.append(dval);
			} else {
				sb.append(" cn");
				sb.append(cn_ctr);
				sb.append("Label=");
				sb.append(dtype);
				sb.append(" cn");
				sb.append(cn_ctr);
				sb.append("=");
				cn_ctr++;
				String dval = Decode.dataToString(obd._type, obd._num);
				sb.append(dval);
			}
		}

		return sb.toString().getBytes(_UTF8);

	  } catch(Exception e){
		throw new ICTITransformException("transform", e);
	  }
	}
}
