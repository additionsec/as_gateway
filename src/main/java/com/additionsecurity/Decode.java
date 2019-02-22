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

import io.vertx.core.json.JsonObject;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.lang.Exception;
import java.lang.StringBuilder;
import java.util.HashMap;
import java.util.Base64;
import java.nio.charset.Charset;

import com.additionsecurity.Utils;

public class Decode {

	private static Base64.Encoder _b64enc = Base64.getEncoder();
	private static JsonObject _jsdef = null;
	private static String _defdesc = "(Definitions not loaded)";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	public static void initDefinitions(String path) throws Exception
	{
		byte[] jsb = Files.readAllBytes(Paths.get(path));
		_jsdef = new JsonObject(new String(jsb, _UTF8));

		if( !_jsdef.containsKey("format") || _jsdef.getInteger("format") != 1 )
			throw new Exception("Bad definitions format field");

		if( !_jsdef.containsKey("version") )
			throw new Exception("Bad definitions version field");
		final String vendor = _jsdef.getString("vendor","(Unspecified vendor)");
		_defdesc = vendor + " " + String.valueOf(_jsdef.getLong("version"));

		if( !_jsdef.containsKey("events") )
			throw new Exception("Definitions missing events key");
		_jsdef = _jsdef.getJsonObject("events");
	}

	public static String definitionsDescription()
	{
		return _defdesc;
	}

	public static String title(long event, long subevent)
	{
		if( _jsdef == null ) return "-";
		final String k = String.valueOf(event);
		if( !_jsdef.containsKey(k) ) return "-";

		final JsonObject ev = _jsdef.getJsonObject(k);
		if( !ev.containsKey("0") ) return "-";
		String basetitle = ev.getString("0","-");
		if( subevent == 0 ) return basetitle;

		final String sk = String.valueOf(subevent);
		final String sv = ev.getString(sk, null);
		if( sv == null ) return basetitle;
		return basetitle + " - " + sv;
	}

	public static String dataToString(int typ, long data)
	{
		// We don't care of the type, it's all just a number
		return String.valueOf(data);
	}

	private static String IPZERO = "0.0.0.0";
	public static String ipv4ToString( byte[] data )
	{
		if( data == null || data.length != 4 ) return IPZERO;
		StringBuilder sb = new StringBuilder();
		int i;
		for( i=0; i<4; i++ ){
			if( i > 0 ) sb.append('.');
			sb.append( (int)(data[i] & 0xff) );
		}
		return sb.toString();
	}

	private static String MACZERO = "00:00:00:00:00:00";
	public static String macToString( byte[] data )
	{
		if( data == null || data.length != 6 ) return MACZERO;
		StringBuilder sb = new StringBuilder();
		int i;
		for( i=0; i<6; i++ ){
			if( i > 0 ) sb.append(':');
			//sb.append( (int)(data[i] & 0xff) );
			sb.append( Integer.toHexString( (int)(data[i] & 0xff) ) );
		}
		return sb.toString();
	}

	private static byte[] BYTEZERO = new byte[]{'0'};
	public static byte[] uint32ToByteString(byte[] data)
	{
		if( data.length == 0 ) return BYTEZERO;
		// Little endian
		long v = 0;
		int i;
		for( i=(data.length - 1); i>=0; i-- ){
			v <<= 8;
			v |= (data[i] & 0xff);
		}
		return String.valueOf(v).getBytes(_UTF8);
	}

	public static byte[] dataToByteString(int typ, byte[] data, ICTITransform t)
	{
		try {

			// Numbers, particularly anything in the range of 6 - 19
			if( (typ == 9 || typ == 19 || typ == 25 || typ == 26 || typ == 22 || typ == 28) )
				return uint32ToByteString(data);

			else if( typ == 11 ) // X509 cert
				return _b64enc.encode( data );

			// Strings; NOTE: we already removed non-strings from the range
			// of 6 - 18, so we just catch that whole range
			else if( (typ >= 6 && typ <= 18) || typ == 23 || (typ >= 29 && typ <= 33) )
				return t.dataToByteString(data);

			else if( typ == 20 )
				return ipv4ToString( data ).getBytes(_UTF8);

			else if( typ == 24 || typ == 34 )
				return macToString( data ).getBytes(_UTF8);

			//else if( typ == 21 )
			//	return "TODO-ipv6-addr".getBytes();

		} catch(Exception e){}

		// everything else is hex
		return Utils.hexBytes(data, false, true);
	}

	public static String dataToString(int typ, byte[] data, ICTITransform t)
	{
		try {
			if( (typ == 9 || typ == 19 || typ == 25 || typ == 26 || typ == 22 || typ == 28) )
				return new String(uint32ToByteString(data), _UTF8);

			else if( typ == 11 ) // X509 cert
				return _b64enc.encodeToString( data );

			// A few items are strings
			else if( (typ >= 6 && typ <= 18) || typ == 23 || (typ >= 29 && typ <= 33) )
				return t.dataToString(data);

			else if( typ == 20 )
				return ipv4ToString( data );

			else if( typ == 24 || typ == 34 )
				return macToString( data );

			//else if( typ == 21 )
			//	return "TODO-ipv6-addr";

		} catch(Exception e){}

		// everything else is hex
		return "0x" + Utils.hex(data);
	}


	private final static String[] _dataTypes = new String[] {
		"UnknownData", //0
		"MD5", //1
		"SHA1", //2
		"SHA256", //3
		"HashAS1", //4
		"HashAS2", //5
		"CVE", //6
		"Version", //7
		"Model", //8
		"ASLibVersion", //9
		"File", //10
		"X509Cert", //11
		"X509CertSubject", //12
		"X509CertIssuer", //13
		"Username", //14
		"Process", //15
		"Command", //16
		"ApplicationTarget", //17 NOTE: can't be "application", conflicts elsewhere
		"String", //18
		"Number", //19
		"IPv4", //20
		"IPv6", //21
		"Port", //22
		"Hostname", //23
		"MAC", //24
		"ConfigTimestamp", //25
		"ASDefVersion", // 26
		"HPKP", // 27
		"VRID", // 28
		"Env", // 29
		"Symbol", // 30
		"PropertyName", // 31
		"Library", // 32
		"SSID", // 33
		"BSSID" // 34
		};

	private static byte[][] _dataTypesBytes = new byte[_dataTypes.length][];
	static {
		for( int i=0; i<_dataTypes.length; i++ ){
			_dataTypesBytes[i] = _dataTypes[i].getBytes(_UTF8);
		}
	}

	public static byte[] dataTypeBytes(int typ)
	{
		if( typ >= _dataTypesBytes.length ) typ = 0;
		return _dataTypesBytes[typ];
	}

	public static String dataType(int typ)
	{
		if( typ >= _dataTypes.length ) typ = 0;
		return _dataTypes[typ];
	}


	private final static String[] _systemTypes = new String[] {
		"Unknown", //0
		"IOS", //1
		"Android", //2
		"WindowsMobile", //3
		"Blackberry", //4
		"AmazonMobile", //5
		"OSX", //6
		"Linux", //7
		"Windows", //8
		"BSD", //9
		"EmbeddedLinux", //10
		"IOT", //11
		"NetworkDevice" //12
		};

	private static byte[][] _systemTypesBytes = new byte[_systemTypes.length][];
	static {
		for( int i=0; i<_systemTypes.length; i++ ){
			_systemTypesBytes[i] = _systemTypes[i].getBytes(_UTF8);
		}
	}
		
	public static byte[] systemTypeBytes(int typ)
	{
		if( typ >= _systemTypesBytes.length ) typ = 0;
		return _systemTypesBytes[typ];
	}

	public static String systemType(int typ)
	{
		if( typ >= _systemTypes.length ) typ = 0;
		return _systemTypes[typ];
	}


	private final static String[] _conf = new String[] {
		"Unknown", //0
		"Low", //1
		"Medium", //2
		"High" //3
		};
	private static byte[][] _confBytes = new byte[_conf.length][];
	static {
		for( int i=0; i<_conf.length; i++ ){
			_confBytes[i] = _conf[i].getBytes(_UTF8);
		}
	}

	public static byte[] confidenceBytes(int conf)
	{
		if( conf >= _confBytes.length ) conf = 0;
		return _confBytes[conf];
	}

	public static String confidence(int conf)
	{
		if( conf >= _conf.length ) conf = 0;
		return _conf[conf];
	}

	private final static String[] _imp = new String[] {
		"Unknown", //0
		"None", //1
		"Minor", //2
		"Moderate", //3
		"Major" //4
		};
	private static byte[][] _impBytes = new byte[_imp.length][];
	static {
		for( int i=0; i<_imp.length; i++ ){
			_impBytes[i] = _imp[i].getBytes(_UTF8);
		}
	}

	public static byte[] impactBytes(int imp)
	{
		if( imp >= _impBytes.length ) imp = 0;
		return _impBytes[imp];
	}

	public static String impact(int imp)
	{
		if( imp >= _imp.length ) imp = 0;
		return _imp[imp];
	}

	private static final String[] _obt = new String[] {
		"Unknown", //0
		"Informational", //1
		"SystemCharacteristics", //2
		"ApplicationCharacteristics", //3
		"MalwareArtifacts", //4
		"NetworkAttack", //5
		"UserBehavior", //6
		"Compliance", //7
		"CustomData" //8
		};
	private static byte[][] _obtBytes = new byte[_obt.length][];
	static {
		for( int i=0; i<_obt.length; i++ ){
			_obtBytes[i] = _obt[i].getBytes(_UTF8);
		}
	}

	public static byte[] observationTypeBytes(int typ)
	{
		if( typ >= _obtBytes.length ) typ = 0;
		return _obtBytes[typ];
	}

	public static String observationType(int typ)
	{
		if( typ >= _obt.length ) typ = 0;
		return _obt[typ];
	}

	private static HashMap<Long,byte[]> _longMap = new HashMap<Long,byte[]>();
	public static byte[] toByteString( long v )
	{
		if( _longMap.containsKey(v) ) return _longMap.get(v);
		byte[] b = String.valueOf(v).getBytes(_UTF8);
		_longMap.put(v, b);
		return b;
	}
}

