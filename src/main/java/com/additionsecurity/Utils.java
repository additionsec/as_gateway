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
import java.nio.charset.Charset;

public class Utils {

	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	public static String hex(byte[] bytes)
	{
		return hex(bytes, false);
	}
	public static String hex(byte[] bytes, boolean shrink)
	{
		if( bytes == null || bytes.length == 0 ) return "00";
		char[] hexChars = new char[bytes.length * 2];

		int end = bytes.length;
		if( shrink ){
			for ( ; end > 0; end-- ){
				if( bytes[end-1] != 0 ) break;
			}
			if( end == 0 ) return "00";
		}

		//for ( int j = 0; j < bytes.length; j++ ) {
		for ( int j = 0; j < end; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars, 0, (end * 2));
	}

	public static byte[] NULL = new byte[]{(byte)'0',(byte)'0'};
	public static byte[] NULL2 = new byte[]{(byte)'0',(byte)'x',(byte)'0',(byte)'0'};

	public static byte[] hexBytes(byte[] bytes, boolean shrink, boolean prefix)
	{
		if( bytes == null || bytes.length == 0 ){
			if( prefix ) return NULL2;
			return NULL;
		}
		int end = bytes.length;
		if( shrink ){
			for ( ; end > 0; end-- ){
				if( bytes[end-1] != 0 ) break;
			}
			if( end == 0 ) {
				if( prefix ) return NULL2;
				return NULL;
			}
		}

		byte[] hexChars;
		int begin = 0;
		if( prefix ){
			hexChars = new byte[(end * 2) + 2]; // for the 0x
			hexChars[0] = (byte)'0';
			hexChars[1] = (byte)'x';
			begin = 2;
		}
		else
			hexChars = new byte[end * 2];

		for ( int j = 0; j < end; j++ ) {
			int v = bytes[j] & 0xFF;
			int k = (j * 2) + begin;
			hexChars[k] = (byte)hexArray[v >>> 4];
			hexChars[k + 1] = (byte)hexArray[v & 0x0F];
		}

		return hexChars;
	}

}
