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

class OutputConsole implements ICTIOutput {

	private static final String DESC = "Console";

	private ICTITransform _transform;

	public OutputConsole(Properties prop, ICTITransform transform) throws Exception
	{
		// Verify transform compatibility
		if( transform == null ) throw new Exception("transform");
		_transform = transform;

		// Push back config signals to transform
		prop.setProperty("transform._recvtimestamp","include");
		transform.reconfigure( prop );
	}

	public String description()
	{
		return DESC;
	}

	public void nowTick(long ts)
	{
		// NO-OP
	}

	public void output(byte[][] datas) throws ICTIOutputException
	{
		try {
			if( datas == null ) return;
			int i;
			for( i=0; i<datas.length; i++ ){
				if( datas[i] == null ) continue;
				System.out.write( datas[i], 0, datas[i].length );
				System.out.println();
			}
		} catch(Exception e){
			// Swallow on purpose
		}
	}
}
