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

public class XForwardedFor {

	public static byte[] NULL = new byte[]{0,0,0,0};

	public static byte[] parse( byte[] data, int start ){
		//long result = 0;
		int octet = 0;
		//int i;
		int ptr = start;

		try {
			byte[] result = new byte[4];

			octet = ( data[ptr++] - '0' );
			if( data[ptr] != '.' ){
				octet = (octet * 10) + (data[ptr++] - '0');
				if( data[ptr] != '.' ){
					octet = (octet * 10) + (data[ptr++] - '0');
				}
			}
			if( octet < 0 || octet > 255 ) throw new Exception();
			result[0] = (byte)octet;

			ptr++;

			octet = ( data[ptr++] - '0' );
			if( data[ptr] != '.' ){
				octet = (octet * 10) + (data[ptr++] - '0');
				if( data[ptr] != '.' ){
					octet = (octet * 10) + (data[ptr++] - '0');
				}
			}
			if( octet < 0 || octet > 255 ) throw new Exception();
			result[1] = (byte)octet;

			ptr++;

			octet = ( data[ptr++] - '0' );
			if( data[ptr] != '.' ){
				octet = (octet * 10) + (data[ptr++] - '0');
				if( data[ptr] != '.' ){
					octet = (octet * 10) + (data[ptr++] - '0');
				}
			}
			if( octet < 0 || octet > 255 ) throw new Exception();
			result[2] = (byte)octet;

			ptr++;

			octet = ( data[ptr++] - '0' );
			if( data.length > ptr && data[ptr] != '.' && data[ptr] != ',' ){
				octet = (octet * 10) + (data[ptr++] - '0');
				if( data.length > ptr && data[ptr] != '.' && data[ptr] != ',' ){
					octet = (octet * 10) + (data[ptr++] - '0');
				}
			}
			if( octet < 0 || octet > 255 ) throw new Exception();
			result[3] = (byte)octet;

			return result;
		}
		catch (Exception e ){
			return NULL;
		}
	}
}
