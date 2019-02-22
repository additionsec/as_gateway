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
import java.lang.ThreadLocal;
import java.util.ArrayList;
import java.util.Properties;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.nio.charset.Charset;

import java.nio.ByteBuffer;

public class TransformCSV3 implements ICTITransform {

	private static final String VER = "1.0";
	private static final String DESC = "CSV";
	private static final byte FORMAT_VER = (byte)'2';

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

		String v = prop.getProperty("transform.accountName2_string","");
		if( "true".equals(v) ) _accountName2String = true;
		else _accountName2String = false;

		v = prop.getProperty("transform.include_organizationId","");
		if( "true".equals(v) ) _includeOrg = true;
		else _includeOrg = false;

		v = prop.getProperty("transform.include_title","");
		if( "true".equals(v) ) _includeTitle = true;
		else _includeTitle = false;

		v = prop.getProperty("transform.systemId2_string","");
		if( "true".equals(v) ) _resource2String = true;
		else _resource2String = false;

		_hostname = " " + prop.getProperty("_hostname","asgw") + " ";
	}

	public TransformCSV3(Properties prop)
	{
		reconfigure(prop);
	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC);
		if( _includeTs ) sb.append("; timestamp=true");
		if( _accountName2String ) sb.append("; accountName2string=true");
		if( _includeOrg ) sb.append("; org=true");
		if( _includeTitle ) sb.append("; title=true");
		return sb.toString();
	}

	public String header()
	{
		String header;

		if( _includeOrg ){
			header = "Format,RecvIp,Organization,AccountId,AccountId2,SystemType,SystemId,SystemId2,Application," +
			"EventID,EventSubId,EventTitle,Timestamp,Category,Confidence,DataCount,Data";
		} else {
			header = "Format,RecvIp,AccountId,AccountId2,SystemType,SystemId,SystemId2,Application," +
			"EventID,EventSubId,EventTitle,Timestamp,Category,Confidence,DataCount,Data";
		}
		return header;
	}

	public boolean isMultiLine()
	{
		return false;
	}

	public String extension()
	{
		return "csv";
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

		byte[] QQ = new byte[]{(byte)'"',(byte)'"'};
		byte[] SX = new byte[]{(byte)'\\',(byte)'x'};

		try {
			for( i=offset; i<data.length; i++){

				// General characters that don't need escaping
				// Special care for quote (34)
				if( data[i] >= 32 && data[i] <= 127 && data[i] != 34 ) continue;

				// Something needs escaping

				// allocate an B if we don't have it
				if( b == null ) b = ByteBuffer.allocate( data.length + 20 );

				// Copy everything up to now to the sb
				if( (i-offset) > 0 )
					b.put( data, offset, (i-offset) );

				// Figure out the escape char
				if( data[i] == 34 ){
					b.put(QQ);
				} else {
					b.put(SX);
					ba[0] = data[i];
					b.put( Utils.hex(ba).getBytes() ); // TODO
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
		byte dc;
	}

	public static byte[] NULL = new byte[]{ (byte)',',(byte)'-' };
	public static byte C = (byte)',';
	public static byte[] COMMAQ = new byte[]{(byte)',',(byte)'"'};
	public static byte[] CD = new byte[]{(byte)',',(byte)'-'};
	public static byte[] QQ = new byte[]{(byte)'"',(byte)'"'};


	private static final ThreadLocal<ByteBuffer> threadBuffer =
		new ThreadLocal<ByteBuffer>() {
			@Override protected ByteBuffer initialValue() {
				return ByteBuffer.allocate(8192);
			}
		};


	public Object groupObject(CTIItem items[]) throws ICTITransformException
	{
		if( items.length == 0 ) return null;
		//ByteBuffer b = ByteBuffer.allocate(4096);
		ByteBuffer b = threadBuffer.get();
		b.rewind();

		CTIItem item = items[0];
		GroupInfo go = new GroupInfo();

		if( _includeTs ){
			b.put( _nowString.getBytes(_UTF8) );
			b.put( _hostname.getBytes(_UTF8) );
		}

		// "Format,RecvIp,(Organization),AccountId,AccountId2,SystemType,SystemId,SystemId2,Application," +
		b.put( FORMAT_VER );

		// RecvIp
		b.put(C).put( Decode.ipv4ToString(item._recvip).getBytes(_UTF8) );

		// Optional organization value
		if( _includeOrg )
			b.put(C).put( Utils.hexBytes(item._org, true, false) );

		// Account ID
		if( item._user != null && item._user.length > 0 ){
			b.put(C).put( Utils.hexBytes(item._user, true, false) );
		}
		else
			b.put( NULL );

		// AccountID2	
		if( item._user2 != null && item._user2.length > 0 ){
			b.put(COMMAQ);
			if( _accountName2String )
				b.put( dataToByteString(item._user2) );
			else
				b.put( Utils.hexBytes(item._user2, true, false) );
			b.put((byte)'"');
		} else 
			b.put( NULL );

		// SystemType
		if( item._sysType > 0 ){
			b.put(C).put( Decode.systemType(item._sysType).getBytes(_UTF8) );
		}
		else
			b.put( NULL );

		// SystemID
		if( item._sys != null && item._sys.length > 0 ) {
			b.put(C).put( Utils.hexBytes(item._sys, true, false) );
		}
		else
			b.put( NULL );

		// SystemID2
		if( item._sys2 != null && item._sys2.length > 0 ){
			b.put(COMMAQ);
			if( _resource2String )
				b.put( dataToByteString(item._sys2) );
			else
				b.put( Utils.hexBytes(item._sys2, true, false) );
			b.put((byte)'"');
		} else
			b.put( NULL );

		// Application
		if( item._app != null && item._app.length > 0 ){
			b.put( COMMAQ ).put( dataToByteString(item._app) ).put((byte)'"');
		}
		else
			b.put( NULL );

		// NOTE: we include the trailing comma here
		b.put(C);

		go.leader = b.position();
		go.b = b;

		return go;
	}


	public byte[] transform(CTIItem item, Object group) throws ICTITransformException
	{
	  try {
		GroupInfo go = (GroupInfo)group;
		ByteBuffer b = (ByteBuffer)go.b.position(go.leader);

		// NOTE: the order here must match the header line!  We already have the leader, so here is what's left:
		//	"EventID,EventSubId,EventTitle,Timestamp,Category,Impact,Confidence,DataCount,Data";

		// EventID, EventSubId
		b.put( Decode.toByteString(item._ob._test) );
		b.put(C).put( Decode.toByteString(item._ob._test2) );

		// EventTitle
		if( _includeTitle )
			b.put(COMMAQ).put(Decode.title(item._ob._test,item._ob._test2).getBytes()).put((byte)'"');
		else
			b.put(CD);

		// Timestamp
		b.put(C).put( strTs(item._ob._ts).getBytes(_UTF8) );

		// Category
		b.put(C).put(Decode.observationTypeBytes(item._ob._type));

		/*
		// Impact
		b.put(C).put(Decode.impactBytes(item._ob._imp));
		*/

		// Confidence
		b.put(C).put(Decode.confidenceBytes(item._ob._conf));

		// DataCount
		go.dc = (byte)(item._ob._datas.size() + 0x30);
		b.put(C).put( go.dc );


		// Extensions are zero or more, in the form:
		// "nom=""val"""
		go.seen.clear();
		for( CTIItem.ObData obd : item._ob._datas ){

			b.mark();

			try {
				String dtype = Decode.dataType(obd._type);
				byte c[];

				// Append _2, _3 for subsequent same key names
				if( go.seen.contains(dtype) ){
					int i = 2;
					String k;
					while(true){
						k = dtype + String.valueOf(i);
						if( !go.seen.contains(k) ) break;
						i = i + 1;
					}
					dtype = k;
				}
				c = dtype.getBytes();
				// Performant way of lowercasing the first character
				c[0] += 32;
				go.seen.add(dtype);

				b.put(COMMAQ).put(c).put((byte)'=');

				if( obd._data != null ){
					b.put(QQ).put( Decode.dataToByteString(obd._type, obd._data, this) ).put(QQ);
				}
				else
					b.put( Decode.dataToString(obd._type, obd._num).getBytes(_UTF8) );
				b.put((byte)'"');

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
