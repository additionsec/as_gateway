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
import java.lang.Exception;
import java.lang.StringBuilder;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.text.DateFormat;
import java.util.Date;
import java.net.InetAddress;
import java.net.Socket;
import java.io.OutputStream;
import java.lang.Integer;
import java.nio.charset.Charset;

import com.additionsecurity.ICTIOutput.ICTIOutputException;

class OutputTcpSyslog implements ICTIOutput {

	private static final String DESC = "TcpSyslog";
	private static final int MAX_SIZE = 65535;

	private static Charset _UTF8 = null;
	static { _UTF8 = Charset.forName("UTF-8"); }

	private String _hostname;

	private String _host;	
	private int _port;
	private InetAddress _addr;

	private Object _os_socket_lock = new Object();
	private OutputStream _os_socket;

	private boolean _bom;
	private int _facility;
	private int _severity;
	private byte[] _h1;
	private byte[] _h2;

	public OutputTcpSyslog(Properties prop, ICTITransform transform) throws Exception
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
		Socket sock = new Socket(_addr, _port);
		_os_socket = sock.getOutputStream();

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
			byte[] b = sb.toString().getBytes(_UTF8);
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

	public void nowTick(long ts)
	{
		// TODO
	}


        private static DateTimeFormatter _formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(ZoneId.systemDefault());

	public void output(byte[][] datas) throws ICTIOutputException
	{
		// TODO: find the largest datas, allocate one byte array w/ header for the largest,
		// then reuse it for everything by copying over existing and just specifying shorter
		// length in the packet send

		// Calculate a header once
		final String ds = _formatter.format(Instant.now());
		final byte[] dsb = ds.getBytes();
		final byte[] header = new byte[ _h1.length + dsb.length + _h2.length ];

		System.arraycopy(_h1, 0, header, 0, _h1.length);
		System.arraycopy(dsb, 0, header, _h1.length, dsb.length);
		System.arraycopy(_h2, 0, header, (_h1.length+dsb.length), _h2.length);

		int i;
		for( i=0; i<datas.length; i++){
			if(datas[i] == null) continue;
			try {
				// NOTE: +6 is room for 5 number chars + space:
				final byte[] payload = new byte[header.length + datas[i].length + 6];
				if( payload.length > MAX_SIZE )
					throw new Exception("Payload size exceeds syslog max");

				System.arraycopy(header, 0, payload, 6, header.length);
				System.arraycopy(datas[i], 0, payload, header.length + 6, datas[i].length);

				// Prefix with the length
				int len = payload.length - 6;
				String len_str = String.valueOf(len) + " ";
				byte[] len_payload = len_str.getBytes(_UTF8);
				int off = 6 - len_payload.length;
				System.arraycopy( len_payload, 0, payload, off, len_payload.length );

				int tries = 2;
				while( tries-- > 0 ){
					synchronized(_os_socket_lock){
						try {
							_os_socket.write( payload, off, (payload.length - off) );
							break;

						} catch(Exception ioe){
							// best effort to close existing socket
							try { _os_socket.close(); }
							catch (Exception e){}

							if( tries == 0 )
								throw new Exception("Connection retry failure");
								// NOTE: this may leave socket unconnected;
								// that's ok, next call will immediately
								// cause exception and get past here with
								// tries == 1

							// refresh/open a new connection
							Socket sock = new Socket(_addr, _port);
							_os_socket = sock.getOutputStream();

							// and loop
						}
					}
				}
			}
			catch(Exception e){
				throw new ICTIOutputException("send",e);
			}
		}
	}
}
