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

import java.util.ArrayList;

public class CTIItem {

	public byte[] _org;
	public byte[] _sys;
	public byte[] _sys2;
	public int _sysType;
	public byte[] _app;
	public byte[] _user;
	public byte[] _user2;
	public long _recvts;
	public byte[] _recvip;
	//public ArrayList<Ob> _obs = new ArrayList<Ob>();
	public Ob _ob;

	public CTIItem cloneBase()
	{
		CTIItem i = new CTIItem();
		i._org = this._org;
		i._sys = this._sys;
		i._sys2 = this._sys2;
		i._sysType = this._sysType;
		i._app = this._app;
		i._user = this._user;
		i._user2 = this._user2;
		i._recvts = this._recvts;
		i._recvip = this._recvip;
		return i;
	}

	public CTIItem setOrgId(byte[] arg){ _org = arg; return this; }
	public CTIItem setSysId(byte[] arg){ _sys = arg; return this; }
	public CTIItem setSysId2(byte[] arg){ _sys2 = arg; return this; }
	public CTIItem setSysType(int arg){ _sysType = arg; return this; }
	public CTIItem setAppId(byte[] arg){ _app = arg; return this; }
	public CTIItem setUserId(byte[] arg){ _user = arg; return this; }
	public CTIItem setUserId2(byte[] arg){ _user2 = arg; return this; }
	//public CTIItem addObservation(Ob arg){ _obs.add(arg); return this; }
	public CTIItem setObservation(Ob arg){ _ob = arg; return this; }
	public CTIItem setRecvTs(long arg){ _recvts = arg; return this; }
	public CTIItem setRecvIp(byte[] arg){ _recvip = arg; return this; }

	public static class Ob {
		public int _type;
		public long _ts;
		public int _conf;
		public int _imp;	// 0=None 3=Low 6=Med 10=High
		public long _test;
		public long _test2;
		public ArrayList<ObData> _datas = new ArrayList<ObData>();

		public Ob setType(int arg){ _type = arg; return this; }
		public Ob setTs(long arg){ _ts = arg; return this; }
		public Ob setConf(int arg){ _conf = arg; return this; }
		public Ob setImp(int arg){ _imp = arg; return this; }
		public Ob setTest(long arg){ _test = arg; return this; }
		public Ob setTest2(long arg){ _test2 = arg; return this; }
		public Ob addData(ObData data){ _datas.add(data); return this; }
	}

	public static class ObData {
		public int _type;
		public byte[] _data;
		public long _num;

		public ObData(int type, byte[] data){
			_type = type;
			_data = data;
		}
		public ObData(int type, long data){
			_type = type;
			_num = data;
		}
	}
}
