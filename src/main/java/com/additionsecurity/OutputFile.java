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

import java.text.DateFormat;
import java.util.Date;
import java.nio.charset.Charset;

import com.additionsecurity.ICTIOutput.ICTIOutputException;

class OutputFile implements ICTIOutput {

	private static final String DESC = "File";

	private String _path;	
	private FileOutputStream _fos;
	private ICTITransform _transform;

	public OutputFile(Properties prop, ICTITransform transform) throws Exception
	{
		// Verify transform compatibility
		if( transform == null ) throw new Exception("transform");
		_transform = transform;

		// Local configuration
		_path = prop.getProperty("output.file.path",null);
		if( _path == null )
			throw new Exception("output.file.path");
		_fos = new FileOutputStream(_path, true);

		// Push back config signals to transform
		prop.setProperty("transform._recvtimestamp","include");
		transform.reconfigure( prop );

		// Write an optional header
		final String header = _transform.header();
		if( header != null ){
			_fos.write( header.getBytes() );
			_fos.write( "\n".getBytes() );
		}

		// Write a startup marker to the file
		final StringBuilder sb = new StringBuilder();
		sb.append("# Service startup ");
		sb.append( DateFormat.getDateTimeInstance().format(new Date()) );
		sb.append("\n");
		_fos.write( sb.toString().getBytes() );
	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC).append("; file=").append(_path);
		return sb.toString();
	}

	public void nowTick(long ts)
	{
		// NO-OP
	}

	public void output(byte[][] datas) throws ICTIOutputException
	{
		try {
			int i;
			for( i=0; i<datas.length; i++){
				if( datas[i] == null ) continue;
				_fos.write( datas[i] );
				_fos.write( 0x0a );
			}
		}
		catch(Exception e){
			throw new ICTIOutputException("write",e);
		}
	}
}
