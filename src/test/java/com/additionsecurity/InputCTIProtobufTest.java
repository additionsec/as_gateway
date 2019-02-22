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

public class InputCTIProtobufTest extends TestCase
{
    public InputCTIProtobufTest( String testName ) {
        super( testName );
    }

    public static Test suite() {
        return new TestSuite( InputCTIProtobufTest.class );
    }


	public void testBasic() throws Exception {
		Properties prop = new Properties();
		ICTIInput ctiin = new InputCTIProtobuf( prop );
		assertNotNull( ctiin );
		assertNotNull( ctiin.description() );

		URL msgu = ClassLoader.getSystemResource("cti_msg.pb");
		File msgf = new File(msgu.toURI());
		Path p = msgf.toPath();
		//byte[] data = Files.readAllBytes(p);
		java.io.ByteArrayInputStream data = new java.io.ByteArrayInputStream( Files.readAllBytes(p) );

		byte[] ip = new byte[4];
		CTIItem[] items = ctiin.process( ip, 0, data );
		assertNotNull( items );
		assertTrue( items.length > 0 );

	}

	public void testPerformance() throws Exception {
		Properties prop = new Properties();
		ICTIInput ctiin = new InputCTIProtobuf( prop );
		assertNotNull( ctiin );

		URL msgu = ClassLoader.getSystemResource("cti_msg.pb");
		File msgf = new File(msgu.toURI());
		Path p = msgf.toPath();
		//byte[] data = Files.readAllBytes(p);
		java.io.ByteArrayInputStream data = new java.io.ByteArrayInputStream( Files.readAllBytes(p) );

		byte[] ip = new byte[4];
		CTIItem[] items;
		int i;

		// warmup
		for( i=0; i<20; i++ ){
			items = ctiin.process( ip, 0, data );
		}

		// actual run
		long t_start = System.currentTimeMillis();
		for( i=0; i<10000; i++ ){
			items = ctiin.process( ip, 0, data );
		}
		long t_stop = System.currentTimeMillis();
		long delta = t_stop - t_start;
		System.out.println("- InputProtobuf perf 10000 msgs in ms: " + String.valueOf(delta));
	}
}
