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

import java.nio.ByteBuffer;

public class TransformKVP2 implements ICTITransform {

	private static final String VER = "1.0";
	private static final String DESC = "KVP";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private boolean _includeOrg = false;
	private boolean _includeTs = false;
	private boolean _includeTitle = false;
	private boolean _accountName2String = false;
	private boolean _resource2String = false;
	private String _hostname = "";
	private byte _hostname_bytes[];

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
		_hostname_bytes = _hostname.getBytes();
	}

	public TransformKVP2(Properties prop)
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
		return "txt";
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
		ByteBuffer b = null;
		int i;
		int offset = 0;
		byte[] ba = new byte[1];

		byte[] SQ = new byte[]{(byte)'\\',(byte)'"'};
		byte[] SE = new byte[]{(byte)'\\',(byte)'='};
		byte[] SS = new byte[]{(byte)'\\',(byte)'\\'};
		byte[] SX = new byte[]{(byte)'\\',(byte)'x'};

		try {
			for( i=offset; i<data.length; i++){

				// General characters that don't need escaping
				if( data[i] >= 32 && data[i] <= 127 && data[i] != 34 &&
					data[i] != 61 && data[i] != 92 ) continue;

				// Something needs escaping

				// allocate an B if we don't have it
				if( b == null ) b = ByteBuffer.allocate( data.length * 2 );

				// Copy everything up to now to the sb
				if( (i-offset) > 0 )
					b.put( data, offset, (i-offset) );

				// Figure out the escape char
				if( data[i] == 34 ) b.put(SQ);
				else if( data[i] == 61 ) b.put(SE);
				else if( data[i] == 92 ) b.put(SS);
				else {
					b.put(SX);
					ba[0] = data[i];
					b.put( Utils.hex(ba).getBytes(_UTF8) ); // TODO
				}

				offset = i + 1;
			}

			if( b == null ){
				// Nothing needed escaping, it's a clean string
				return data;
			}

			if( (data.length - offset) > 0 ){
				// Need to push the trailer into the b
				b.put( data, offset, (data.length-offset) );
			}

			byte result[] = new byte[ b.position() ];
			b.rewind();
			b.get( result );
			return result;

		} catch(Exception e){
			// Something went awry, just return hex encoded data
			return Utils.hexBytes(data, false, true);
		}
	}

        public String dataToString(byte[] data) throws ICTITransformException
        {
		return new String( dataToByteString(data), _UTF8 );
        }

	private static class GroupInfo
	{
		ByteBuffer b;
		int leader;
		HashSet<String> seen = new HashSet<String>();
	}

	public static byte[] RECVIP = "recvIp=".getBytes();
	public static byte[] C_ACCT = ", accountId=".getBytes();
	public static byte[] C_ACCT2_Q = ", accountId2=\"".getBytes();
	public static byte[] C_SYSTYPE = ", systemType=".getBytes();
	public static byte[] C_SYSID = ", systemId=".getBytes();
	public static byte[] C_SYSID2_Q = ", systemId2=\"".getBytes();
	public static byte[] C_APP_Q = ", application=\"".getBytes();
	public static byte[] C_ORG = ", org=".getBytes();
	public static byte[] C_EVENTID = ", eventId=".getBytes();
	public static byte[] C_EVENTSUBID = ", eventSubId=".getBytes();
	public static byte[] C_TITLE_Q = ", title=\"".getBytes();
	public static byte[] C_TS = ", ts=".getBytes();
	public static byte[] C_CAT = ", cat=".getBytes();
	public static byte[] C_SEV = ", sev=".getBytes();
	public static byte[] C_CONF = ", conf=".getBytes();
	public static byte[] C_S = ", ".getBytes();

	public Object groupObject(CTIItem items[]) throws ICTITransformException
	{
		if( items.length == 0 ) return null;
		ByteBuffer b = ByteBuffer.allocate(4096);

		CTIItem item = items[0];
		GroupInfo go = new GroupInfo();

		if( _includeTs ){
			//b.put( _formatter.format(Instant.now()).getBytes() );
			b.put( _nowString.getBytes(_UTF8) );
			b.put( _hostname_bytes );
			//String s = _formatter.format(Instant.now()) + _hostname;
			//b.put( s.getBytes() );
		}

		b.put( RECVIP ).put( Decode.ipv4ToString(item._recvip).getBytes(_UTF8) );

		if( _includeOrg )
			b.put(C_ORG).put( Utils.hexBytes(item._org, true, false) );

		// Account ID
		if( item._user != null && item._user.length > 0 ){
			b.put(C_ACCT).put( Utils.hexBytes(item._user, true, false) );
		}

		// AccountID2	
		if( item._user2 != null && item._user2.length > 0 ){
			b.put(C_ACCT2_Q);
			if( _accountName2String )
				b.put( dataToByteString(item._user2) );
			else
				b.put( Utils.hexBytes(item._user2, true, false) );
			b.put((byte)'"');
		}

		// SystemType
		if( item._sysType > 0 ){
			b.put(C_SYSTYPE).put( Decode.systemTypeBytes(item._sysType) );
		}

		// SystemID
		if( item._sys != null && item._sys.length > 0 ) {
			b.put(C_SYSID).put( Utils.hexBytes(item._sys, true, false) );
		}

		// SystemID2
		if( item._sys2 != null && item._sys2.length > 0 ){
			b.put(C_SYSID2_Q);
			if( _resource2String )
				b.put( dataToByteString(item._sys2) );
			else
				b.put( Utils.hexBytes(item._sys2, true, false) );
			b.put((byte)'"');
		}

		// Application
		if( item._app != null && item._app.length > 0 ){
			b.put( C_APP_Q ).put( dataToByteString(item._app) ).put((byte)'"');
		}

		go.leader = b.position();
		go.b = b;

		return go;
	}

	public byte[] transform(CTIItem item, Object group) throws ICTITransformException
	{
	  try {
		GroupInfo go = (GroupInfo)group;
		ByteBuffer b = (ByteBuffer)go.b.position(go.leader);

		b.put(C_EVENTID).put( Decode.toByteString(item._ob._test) );
		if( item._ob._test2 > 0 )
			b.put(C_EVENTSUBID).put( Decode.toByteString(item._ob._test2) );
		if( _includeTitle )
			b.put(C_TITLE_Q).put(Decode.title(item._ob._test,item._ob._test2).getBytes(_UTF8)).put((byte)'"');

		b.put(C_TS).put( strTs(item._ob._ts).getBytes(_UTF8) );
		if( item._ob._type > 0 ) b.put(C_CAT).put( Decode.observationTypeBytes(item._ob._type) );
		if( item._ob._imp > 0 ) b.put(C_SEV).put(Decode.impactBytes(item._ob._imp) );
		if( item._ob._conf > 0 ) b.put(C_CONF).put(Decode.confidenceBytes(item._ob._conf) );

		go.seen.clear();
		for( CTIItem.ObData obd : item._ob._datas ){

			// Mark our current position
			b.mark();

			try {
				String dtype = Decode.dataType(obd._type);
				byte c[];

				// Append _2, _3 for subsequent same key names (since LEEF doesn't allow
				// dupes)
				if( go.seen.contains(dtype) ){
					int i = 2;
					String k;
					while(true){
						k = dtype + "_" + String.valueOf(i);
						if( !go.seen.contains(k) ) break;
						i = i + 1;
					}
					dtype = k;
				}
				c = dtype.getBytes();
				c[0] += 32; // lowercase
				go.seen.add(dtype);
	
				b.put(C_S).put(c).put((byte)'=');

				if( obd._data != null )
					b.put((byte)'"').put(Decode.dataToByteString(obd._type, obd._data, this)).put((byte)'"');
				else
					b.put( Decode.dataToString(obd._type, obd._num).getBytes(_UTF8) );
			}
			catch( java.nio.BufferOverflowException e ){
				// Too much data, reset to the last mark, which will
				// preserve what we already have, and skip this data item
				b.reset();
				App.reportDroppedData();
			}
		}

		byte result[] = new byte[ b.position() ];
		b.rewind();
		b.get( result );
		return result;

	  } catch(Exception e){
		throw new ICTITransformException("transform", e);
	  }
	}
}
