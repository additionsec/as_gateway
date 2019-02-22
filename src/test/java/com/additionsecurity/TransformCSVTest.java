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

public class TransformCSVTest extends TestCase
{
    public TransformCSVTest( String testName ) {
        super( testName );
    }

	public static CTIItem[] _items;
	public static Properties _prop;
	public static ICTITransform _transform;

    public static Test suite() {
        return new TestSuite( TransformCSVTest.class );
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
		assertTrue( _items.length > 0 );
	}


	public void testBasic() throws Exception {
		_transform = new TransformCSV3( _prop );

		_transform.reconfigure(_prop);
		long ts = System.currentTimeMillis() / 1000;
		_transform.nowTick(ts);
		assertNotNull( _transform.description() );
		assertNotNull( _transform.header() );
		assertFalse( _transform.isMultiLine() );
		assertTrue( "csv".equals(_transform.extension()) );

		Object go = _transform.groupObject(_items);
		for( CTIItem item : _items ){
			byte[] res = _transform.transform(item, go);
			assertNotNull( res );
			assertTrue( res.length > 0 );
		}
	}
	
}
