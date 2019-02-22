package com.additionsecurity;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.net.URL;
import java.io.File;
import java.util.Properties;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;

import com.additionsecurity.*;

public class TransformAllPerfTest extends TestCase
{
    public TransformAllPerfTest( String testName ) {
        super( testName );
    }

	public static CTIItem[] _items;
	public static Properties _prop;

    public static Test suite() {
        return new TestSuite( TransformAllPerfTest.class );
    }

	protected void setUp() throws Exception {
		_prop = new Properties();
		//prop.setProperty("transform.cef.includeTitle","true");
		_prop.setProperty("transform.accountName2String","true");
		_prop.setProperty("transform.resource2String","true");
		_prop.setProperty("_hostname","unitester");

		ICTIInput ctiin = new InputCTIProtobuf( _prop );
		URL msgu = ClassLoader.getSystemResource("cti_msg.pb");
		File msgf = new File(msgu.toURI());
		Path p = msgf.toPath();
		//byte[] data = Files.readAllBytes(p);
		java.io.ByteArrayInputStream data = new java.io.ByteArrayInputStream( Files.readAllBytes(p) );
		byte[] ip = new byte[4];
		_items = ctiin.process( ip, 0, data );
		assertNotNull( _items );
		assertTrue( _items.length >= 2 );
	}

	public void testPerformance() throws Exception {
		long ts = System.currentTimeMillis() / 1000;

		ICTITransform t_json = new TransformJSON( _prop );
		t_json.reconfigure(_prop);
		t_json.nowTick(ts);

		ICTITransform t_cef = new TransformCEF( _prop );
		t_cef.reconfigure(_prop);
		t_cef.nowTick(ts);

		ICTITransform t_leef = new TransformLEEF( _prop );
		t_leef.reconfigure(_prop);
		t_leef.nowTick(ts);

		/*
		ICTITransform t_kvp = new TransformKVP( _prop );
		t_kvp.reconfigure(_prop);
		*/

		ICTITransform t_kvp2 = new TransformKVP2( _prop );
		t_kvp2.reconfigure(_prop);
		t_kvp2.nowTick(ts);

		/*
		ICTITransform t_csv = new TransformCSV( _prop );
		t_csv.reconfigure(_prop);

		ICTITransform t_csv2 = new TransformCSV2( _prop );
		t_csv2.reconfigure(_prop);
		*/

		ICTITransform t_csv3 = new TransformCSV3( _prop );
		t_csv3.reconfigure(_prop);
		t_csv3.nowTick(ts);

		ICTITransform _t;
		CTIItem item = _items[1];
		CTIItem items[] = new CTIItem[]{ item };
		int i;
		byte[] res;
		long t_start, t_stop, delta;

		final int max = 20000;

		_t = t_json;	
		Object go = _t.groupObject(items);
		for( i=0; i<100; i++) res = _t.transform(item, go);
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go);
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- JSON in ms: " + String.valueOf(delta));

		/*
		_t = t_kvp;	
		go = _t.groupObject(items, "");
		for( i=0; i<100; i++) res = _t.transform(item, go, "");
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go, "");
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- KVP in ms: " + String.valueOf(delta));
		*/

		_t = t_kvp2;	
		go = _t.groupObject(items);
		for( i=0; i<100; i++) res = _t.transform(item, go);
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go);
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- KVP2 in ms: " + String.valueOf(delta));

		/*
		_t = t_csv;	
		go = _t.groupObject(items, "");
		for( i=0; i<100; i++) res = _t.transform(item, go, "");
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go, "");
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- CSV in ms: " + String.valueOf(delta));

		_t = t_csv2;	
		go = _t.groupObject(items, "");
		for( i=0; i<100; i++) res = _t.transform(item, go, "");
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go, "");
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- CSV2 in ms: " + String.valueOf(delta));
		*/

		_t = t_csv3;	
		go = _t.groupObject(items);
		for( i=0; i<100; i++) res = _t.transform(item, go);
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go);
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- CSV3 in ms: " + String.valueOf(delta));

		_t = t_cef;	
		go = _t.groupObject(items);
		for( i=0; i<100; i++) res = _t.transform(item, go);
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go);
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- CEF in ms: " + String.valueOf(delta));

		_t = t_leef;	
		go = _t.groupObject(items);
		for( i=0; i<100; i++) res = _t.transform(item, go);
		t_start = System.currentTimeMillis();
		for( i=0; i< max; i++ ) res = _t.transform(item, go);
		t_stop = System.currentTimeMillis();
		delta = t_stop - t_start;
		System.out.println("- LEEF in ms: " + String.valueOf(delta));
	}
}
