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

import java.util.Properties;
import java.io.FileOutputStream;
import java.lang.Exception;
import java.lang.StringBuilder;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.text.DateFormat;
import java.util.Date;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.lang.Integer;
import java.nio.charset.Charset;

import com.additionsecurity.ICTIOutput.ICTIOutputException;

class OutputUdpSyslog implements ICTIOutput {

	private static final String DESC = "UdpSyslog";

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private String _hostname;

	private String _host;	
	private int _port;
	private InetAddress _addr;
	private DatagramSocket _socket;

	private boolean _bom;
	private int _facility;
	private int _severity;
	private byte[] _h1;
	private byte[] _h2;

	public OutputUdpSyslog(Properties prop, ICTITransform transform) throws Exception
	{
		// Verify transform compatibility
		if( transform == null ) throw new Exception("transform");
		if( transform.isMultiLine() )
			throw new Exception("transform not compatible with syslog output");

		// Local configuration
		_host = prop.getProperty("output.syslog.host",null);
		if( _host == null ) throw new Exception("output.syslog.host");

		_port = Integer.parseInt(prop.getProperty("output.syslog.port", "514"));
		if( _port < 0 || _port > 65535 ) throw new Exception("output.syslog.port");

		_facility = Integer.parseInt(prop.getProperty("output.syslog.facility", "16")); // LOCAL0
		if( _facility < 0 || _facility > 23 ) throw new Exception("output.syslog.facility");

		_severity = Integer.parseInt(prop.getProperty("output.syslog.severity", "6")); // Informational
		if( _severity < 0 || _severity > 7 ) throw new Exception("output.syslog.severity");

		String v = prop.getProperty("output.syslog.bom","");
		if( v.equals("true") ) _bom = true;

		_hostname = prop.getProperty("_hostname","asgw");

		// Look up the hostname
		_addr = InetAddress.getByName(_host);
		_socket = new DatagramSocket();
		_socket.connect(_addr,_port);

		// Precalculation of static values (basically, everything but the timestamp)
		StringBuilder sb = new StringBuilder();

		// PIECE1 = PRI VERSION SP
		sb.append("<");
		long prival = (_facility * 8) + _severity;
		sb.append(prival);
		sb.append(">1 ");
		_h1 = sb.toString().getBytes(_UTF8);

		// PIECE2 = SP HOSTNAME SP APPNAME SP PROCID SP MSGID SP STRUCT-DATA SP
		sb.setLength(0);
		sb.append(" ").append(_hostname).append(" ASGW - - - ");
		if( _bom ){
			byte[] b = sb.toString().getBytes();
			_h2 = new byte[ b.length + 3 ];
			System.arraycopy(_h2, 0, b, 0, b.length);
			_h2[ _h2.length - 3 ] = (byte)0xef;
			_h2[ _h2.length - 2 ] = (byte)0xbb;
			_h2[ _h2.length - 1 ] = (byte)0xbf;
		} else {
			_h2 = sb.toString().getBytes(_UTF8);
		}
	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC).append("; host=").append(_host);
		sb.append("; port=").append(_port);
		sb.append("; facility=").append(_facility);
		sb.append("; severity=").append(_severity);
		return sb.toString();
	}


        private static DateTimeFormatter _formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(ZoneId.systemDefault());

	public void nowTick(long ts)
	{
		_datestamp = _formatter.format(Instant.now()).getBytes();

	}
	private byte[] _datestamp;

	public void output(byte[][] datas) throws ICTIOutputException
	{
		// Calculate a header once
		/*
		final String ds = _formatter.format(Instant.now());
		final byte[] dsb = ds.getBytes();
		*/

		/*
		final byte[] header = new byte[ _h1.length + dsb.length + _h2.length ];
		System.arraycopy(_h1, 0, header, 0, _h1.length);
		System.arraycopy(dsb, 0, header, _h1.length, dsb.length);
		System.arraycopy(_h2, 0, header, (_h1.length+dsb.length), _h2.length);
		*/

		// Find largest data item
		int i, largest=0;
		for( i=0; i<datas.length; i++){
			if( datas[i] == null ) continue;
			// TODO:
			if( datas[i].length > 65535 ) throw new ICTIOutputException("Message item size exceeds max");
			if( datas[i].length > largest ) largest = datas[i].length;
		}

		// Now allocate one byte buffer that can fit everything
		byte[] ds = _datestamp; // Get ref due to TOCTOU
		final int o = _h1.length + ds.length + _h2.length;
		final byte[] payload = new byte[ o + largest ];
		System.arraycopy(_h1, 0, payload, 0, _h1.length);
		System.arraycopy(ds, 0, payload, _h1.length, ds.length);
		System.arraycopy(_h2, 0, payload, (_h1.length+ds.length), _h2.length);
		
		for( i=0; i<datas.length; i++){
			if( datas[i] == null ) continue;
			try {
				System.arraycopy(datas[i], 0, payload, o, datas[i].length);
				final DatagramPacket packet = new DatagramPacket(payload, (o + datas[i].length));
				_socket.send(packet);
			}
			catch(Exception e){
				throw new ICTIOutputException("send",e);
			}
		}
	}
}
