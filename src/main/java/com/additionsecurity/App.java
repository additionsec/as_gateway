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

import io.vertx.core.eventbus.EventBus;
import io.vertx.core.*;
import io.vertx.ext.web.*;
import io.vertx.core.Vertx;
import io.vertx.core.net.*;
import io.vertx.core.VertxOptions;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.core.http.*;
import io.vertx.core.buffer.Buffer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;

import java.util.HashSet;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.lang.IllegalArgumentException;
import java.util.concurrent.atomic.AtomicLong;
import java.nio.charset.Charset;
import java.io.File;
import java.security.*;

import com.additionsecurity.Decode;

public class App
{
    public static final boolean DEBUG = false;

    private static final String DESC = "ASGateway";
    public static final String VER = "1.5";
    public static final int IVER = 2017082101;
    private static final String ROUTE = "/v1/msg";
    private static final String ROUTE_HEALTH = "/";
    private static final int COUNTER_MS = (1000 * 60 * 60 * 4); // 4 hours

    private static final int API_PORT = 443;
    private static final boolean API_SSL = true;
    private static final String API_HOST = "api.additionsecurity.com";
    private static final String ERR_PATH = "/asgw/1/er";
    private static final String STATS_PATH = "/asgw/1/health";

    private static Charset _UTF8 = null;
    static { _UTF8 = Charset.forName("UTF-8"); }

    private long _maxSize = (64 * 1024);
    private String _uploadDir;
    private int _listenPort;
    private boolean _saveIp = true;
    private String _keystorePath = null;
    private String _keystorePassword = null;

    private volatile long _currentTs = 0;
    private volatile String _transformNow;

    private static ICTIInput _input = null;
    private static ICTITransform _transform = null;
    private static ICTIOutput _output = null;

    public static Vertx vertx = null;
    private static EventBus _eb;

    private static String _hpkp_header = null;

    private static String OS = System.getProperty("os.name").toLowerCase();
    public static String _hostname = "unknown";
    public static String _address = "0.0.0.0";
    public static String _strInput = "-";
    public static String _strTransform = "-";
    public static String _strOutput = "-";

    private static boolean _errVerticleReady = false;
 
    public static void main( String[] args )
    {
	try {
		// Figure out our local hostname & address, for any error reporting
		_hostname = InetAddress.getLocalHost().getHostName();
		_address = InetAddress.getLocalHost().getHostAddress();

		Properties prop = new Properties();

		// Disable vertx caching
		Properties sysprops = System.getProperties();
		sysprops.setProperty("vertx.disableFileCaching", "true");
		//sysprops.setProperty("java.net.preferIPv4Stack", "true");

		if( args.length >= 1 ){
			try {
				FileInputStream input = new FileInputStream( args[0] );
				prop.load(input);
				input.close();
			}
			catch (IOException ex){
				System.out.println("Error: config.properties parsing exception:");
				err(ex);
				try {Thread.sleep(30000); } catch(Exception e){}
				System.exit(1);
			}
		} else {
			System.out.println("Error: config.properties not specified on command line");
			err(new Exception("config.properties not specified"));
			try {Thread.sleep(30000); } catch(Exception s){}
			System.exit(1);
		}

		// This special handling of port is related to EC2/ElasticBeanstalk
		String v = System.getProperty("PORT");
		if( v != null ) prop.setProperty( "port", v );


		try {
			new App(prop).run();
		}
		catch(Exception e){
			System.out.println("Error: application did not execute correctly");
			err(e);
			try {Thread.sleep(30000); } catch(Exception s){}
			System.exit(1);
		}
	}
	catch(Exception e){
		System.out.println("Error: application did not execute correctly");
		err(e);
		try {Thread.sleep(30000); } catch(Exception s){}
		System.exit(1);
	}
    }

    public App(Properties props) throws Exception
    {
	// Our global context/instance
	VertxOptions vo = new VertxOptions();
	//vo.setBlockedThreadCheckInterval(500);
	vo.setInternalBlockingPoolSize(80).setWorkerPoolSize(80);
	vertx = Vertx.vertx(vo);

	// HTTP listener configuration items
	_maxSize = Long.parseLong( props.getProperty("max_size","65536") );
	_uploadDir = System.getProperty("java.io.tmpdir");
	_listenPort = Integer.parseInt( props.getProperty("port","5000") );
	String v = props.getProperty("save_ip","");
	if( "false".equals(v) ) _saveIp = false;
	_hpkp_header = props.getProperty("hpkp_header", null);

	_keystorePath = props.getProperty("ssl_keystore", null);
	if( _keystorePath != null ){
		final File f = new File(_keystorePath);
		if(!f.exists()){
			System.out.println("Error: keystore files does not exist");
			throw new IllegalArgumentException("Keystore does not exist");
		}
	}
	_keystorePassword = props.getProperty("ssl_keystore_password", null);
	if( _keystorePath != null && _keystorePassword == null ){
		System.out.println("Error: keystore without keystore password specified");
		throw new IllegalArgumentException("Keystore without keystore password");
	}

	props.setProperty("_hostname", _hostname);

	// Optionally load definitions
	final String defs = props.getProperty("definitions",null);
	if( defs != null ){
		try {
			Decode.initDefinitions(defs);
		}
		catch(Exception e){
			System.out.println("Error: definitions parsing error");
			err(e);
			try {Thread.sleep(30000); } catch(Exception s){}
			System.exit(1);
		}
	}

	// Figure out the desired transform
	_strTransform = props.getProperty("transform","");
	if( _strTransform.equals("leef") ){ _transform = new TransformLEEF(props);
	} else if( _strTransform.equals("cef") ){ _transform = new TransformCEF(props);
	} else if( _strTransform.equals("kvp") ){ _transform = new TransformKVP2(props);
	} else if( _strTransform.equals("json") ){ _transform = new TransformJSON(props);
	} else if( _strTransform.equals("csv") ){ _transform = new TransformCSV3(props);
	} else {
		System.out.println("Unrecognized 'transform' value in configuration");
		throw new IllegalArgumentException("bad 'transform' value '" + _strTransform + "'");
	}	

	// Figure out the desired output
	_strOutput = props.getProperty("output","");
	if( _strOutput.equals("file") ){ _output = new OutputFile(props, _transform);
	} else if( _strOutput.equals("udpsyslog") ){ _output = new OutputUdpSyslog(props, _transform);
	} else if( _strOutput.equals("tcpsyslog") ){ _output = new OutputTcpSyslog(props, _transform);
	} else if( _strOutput.equals("s3") ){ _output = new OutputS3(props, _transform);
	} else if( _strOutput.equals("sumologic") ){ _output = new OutputSumoLogic(props, _transform);
	} else if( _strOutput.equals("sinkhole") ){ _output = new OutputSinkhole(props, _transform);
	} else if( _strOutput.equals("console") ){ _output = new OutputConsole(props, _transform);
	} else {
		System.out.println("Unrecognized 'output' value in configuration");
		throw new IllegalArgumentException("bad 'output' value '" + _strOutput + "'");
	}

	// Figure out the desired input
	_strInput = props.getProperty("input","protobuf");
	if( _strInput.equals("protobuf") ){ _input = new InputCTIProtobuf(props);
	} else {
		System.out.println("Unrecognized 'input' value in configuration");
		throw new IllegalArgumentException("bad 'input' value '" + _strInput + "'");
	}

	// Display the basic configuration
	System.out.print(DESC);
	System.out.print(" ");
	System.out.println(VER);
	System.out.print("- Upload/temp dir: ");
	System.out.println( _uploadDir );
	System.out.print("- Definitions: ");
	System.out.println( Decode.definitionsDescription() );
	System.out.print("- Input: ");
	System.out.println( _input.description() );
	System.out.print("- Transform: ");
	System.out.println( _transform.description() );
	System.out.print("- Output: ");
	System.out.println( _output.description() );
	if( App.DEBUG ) System.out.println("- NON-PRODUCTION DEBUG BUILD");

	_eb = App.vertx.eventBus();

	// Configure our error verticle
	DeploymentOptions options = new DeploymentOptions().setWorker(true);
	ErrorWorkerVerticle verticle = new ErrorWorkerVerticle();
	App.vertx.deployVerticle(verticle, options, res-> {
		if( !res.succeeded() ){
			System.out.println("Error: Error Worker Startup Failed");
			err( res.cause() );
			try{ Thread.sleep(30000); } catch(Exception e){}
			System.exit(1);
		} else {
			_errVerticleReady = true;
		}
	});

	// Configure our stats verticle
	StatsWorkerVerticle sverticle = new StatsWorkerVerticle();
	App.vertx.deployVerticle(sverticle, options, res-> {
		if( !res.succeeded() ){
			System.out.println("Error: Stats Worker Startup Failed");
			err( res.cause() );
			try { Thread.sleep(30000); } catch(Exception s){}
			System.exit(1);
		} else {
			// Send stats immediately, which also "registers" this gw
			_eb.send("cti.stats", counterPayload());
		}
	});

	// Initial values
	_currentTs = System.currentTimeMillis() / 1000;
	_transform.nowTick(_currentTs);
	_output.nowTick(_currentTs);

	// Send a startup test output message
	// UPDATE: skip if we're using console output
	if( !_strOutput.equals("console") ){
		try {
			CTIItem item = new CTIItem();
			item.setRecvIp( new byte[4] );
			item.setAppId("com.additionsecurity.startup.test".getBytes(_UTF8));
			item.setRecvTs( System.currentTimeMillis() / 1000 );
			CTIItem.Ob ob = new CTIItem.Ob();
			ob.setTs( System.currentTimeMillis() / 1000 );
			item.setObservation(ob);

			byte[][] binary_items = new byte[1][];
			final CTIItem items[] = new CTIItem[] { item };
			_transform.nowTick( System.currentTimeMillis() / 1000 );
			final Object go = _transform.groupObject( items );
			binary_items[0] = _transform.transform(item, go);
			_output.output( binary_items );
		}
		catch(Exception e){
			System.out.println("Error: Unable to perform a startup transform & output");
			err(e);
			System.exit(1);
		}
	}


	// Set a shutdown hook that sends final stats
	Runtime.getRuntime().addShutdownHook(new Thread(){
		public void run(){
			_eb.send("cti.stats", counterPayload());
			try { Thread.sleep(10000); } catch(Exception e){}
		}
	});
    }

    private static HashSet<String> _prior = new HashSet<String>();
    public static void err(Throwable t)
    {
		if( t == null ) return;
		if( App.DEBUG ) t.printStackTrace();

		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		t.printStackTrace(pw);
		final String st = sw.toString();

		// If we've seen this one before, don't complain again
		if( _prior.contains(st) ) return;

		_prior.add(st);
		if( _errVerticleReady )
			_eb.send("cti.err", st);
		else
			ErrorWorkerVerticle.immediate(st);
    }

    final static AtomicLong counterOK = new AtomicLong();
    final static AtomicLong counterErr = new AtomicLong();
    final static AtomicLong counterErrInput = new AtomicLong();
    final static AtomicLong counterErrTransform = new AtomicLong();
    final static AtomicLong counterErrOutput = new AtomicLong();
    final static AtomicLong counterDroppedInput = new AtomicLong();
    final static AtomicLong counterDroppedData = new AtomicLong();

    public static void reportDroppedData()
    {
	counterDroppedData.getAndIncrement();
    }

    public byte[] counterPayload()
    {
	final long cOK = counterOK.getAndSet(0);
	final long cErr = counterErr.getAndSet(0);
	final long cErrI = counterErrInput.getAndSet(0);
	final long cErrT = counterErrTransform.getAndSet(0);
	final long cErrO = counterErrOutput.getAndSet(0);
	final long cDrop = counterDroppedInput.getAndSet(0);
	final long cDropD = counterDroppedData.getAndSet(0);

	Buffer b = Buffer.buffer(7 * 8);
	b.appendLong(cOK).appendLong(cErr).appendLong(cErrI);
	b.appendLong(cErrT).appendLong(cErrO).appendLong(cDrop);
	b.appendLong(cDropD);
	return b.getBytes();
    }

    public void run()
    {
	final Router router = Router.router(vertx);

	// We only update the receive timestamp ever X seconds
	vertx.setPeriodic(2000, id -> {
		_currentTs = System.currentTimeMillis() / 1000;
		_transform.nowTick(_currentTs);
		_output.nowTick(_currentTs);
	});

	// Our error counter handler
	vertx.setPeriodic( COUNTER_MS, id -> {
		_eb.send("cti.stats", counterPayload() );
	});


	// Route handling - GET for the msg handler
	Route routePing = router.route(ROUTE).method(HttpMethod.GET).handler( routingContext -> {
			routingContext.response().setStatusCode(200);
			if( _hpkp_header != null ) routingContext.response().putHeader("Public-Key-Pins", _hpkp_header);
			routingContext.response().end();
		});


	// Route handling - initial POST body upload
	final Route route1 = router.route(ROUTE).method(HttpMethod.POST);
	final BodyHandler bodyHandler = BodyHandler.create();
	bodyHandler.setBodyLimit( _maxSize );
	bodyHandler.setUploadsDirectory( _uploadDir );
	route1.handler( bodyHandler );

	// Route handling - process body, transform, and output
	final Route route2 = router.route(ROUTE).method(HttpMethod.POST);
	route2.blockingHandler( routingContext -> {

		try {
			// Retrieve the body bytes
			final ByteBuf body = routingContext.getBody().getByteBuf();
			final ByteBufInputStream bbis = new ByteBufInputStream( body, body.readableBytes() );
			final long ts = _currentTs; 

			// Get the received IP, if desired
			byte[] ip = new byte[4];
			if( _saveIp ){
				final String xff = routingContext.request().getHeader("X-Forwarded-For");
				if( xff != null )
					ip = XForwardedFor.parse( xff.getBytes(), 0 );
				else {
					final String ra = routingContext.request().remoteAddress().host();
					ip = XForwardedFor.parse( ra.getBytes(), 0 );
				}
			}

			CTIItem[] items;
			try {
				items = _input.process(ip, ts, bbis);
			}
			catch(Throwable t){
				counterErrInput.getAndIncrement();
				err(t);
				routingContext.response().setStatusCode(500);
				routingContext.next();
				return;
			}
			// items == null if the report is to be discarded
			if( items == null ){
				counterDroppedInput.getAndIncrement();
				err( new Throwable("Null items") );
			} else {
				byte[][] binary_items = new byte[items.length][];
				int i;
				Object go = _transform.groupObject(items);
				for(i=0; i<items.length; i++){
					if( items[i] == null ) continue;
					try {
						binary_items[i] = _transform.transform( items[i], go );
					}
					catch(Throwable t){
						counterErrTransform.getAndIncrement();
						err(t);
						// TODO continue to other items?  This item may
						// replay and keep hitting the bug
						routingContext.response().setStatusCode(500);
						routingContext.next();
						return;
					}
				}
				try {
					_output.output( binary_items );
				}
				catch(Throwable t){
					counterErrOutput.getAndIncrement();
					err(t);
					routingContext.response().setStatusCode(500);
					routingContext.next();
					return;
				}
			}
		}
		catch(Throwable e){
			err(e);
			counterErr.getAndIncrement();
			routingContext.response().setStatusCode(500);
			routingContext.next();
			return;
		}

		counterOK.getAndIncrement();
		routingContext.response().setStatusCode(200);
		if( _hpkp_header != null ) routingContext.response().putHeader("Public-Key-Pins", _hpkp_header);
		routingContext.next();

	}, false);

	// Route handling - finish the request
	// NOTE: there is/was a bug in vertx where response.end() on a blocking handler didn't
	// correctly end, it required leaving the blocking handler and ending on a non-blocking handler
	final Route route3 = router.route(ROUTE).method(HttpMethod.POST).handler( routingContext -> {
			routingContext.response().end();
		});

	// Route handling - we have a simple route handler for ELB health requests
	Route routeHealth = router.route(ROUTE_HEALTH).method(HttpMethod.GET).handler( routingContext -> {
			routingContext.response().setStatusCode(200);
			routingContext.response().end();
		});


	// Global error handler, to catch any problems in HTTP handling
	router.route().failureHandler( ctx -> {
			Throwable t = (Throwable) ctx.failure();
			App.err( ctx.failure() );
			ctx.response().setStatusCode(500);
			ctx.response().end();
		});
	
	// Run the HTTP server
	try {
		HttpServerOptions hso = new HttpServerOptions().setAcceptBacklog(40000).setUsePooledBuffers(true);

		// Should we configure SSL?
		if( _keystorePath != null && _keystorePassword != null ){
			// Enable SSL
			displayKeystorePin();
			System.out.println("Ready to receive requests on port " + String.valueOf(_listenPort) + " (HTTPS)");
			hso.setSsl(true).setKeyStoreOptions( new JksOptions().setPath(_keystorePath).setPassword(_keystorePassword));
		} else {
			System.out.println("Ready to receive requests on port " + String.valueOf(_listenPort));
		}

		vertx.createHttpServer( hso ).requestHandler(router::accept).listen(_listenPort);
	}
	catch(Throwable t){
		err(t);
		System.exit(2);
	}
    }


	private void displayKeystorePin() 
	{
		try {
			final KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(_keystorePath);
				ks.load(fis, _keystorePassword.toCharArray());
			} finally {
				if( fis != null ) fis.close();
			}

			final String firstAlias = ks.aliases().nextElement();
			final KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry)ks.getEntry(firstAlias, 
				new KeyStore.PasswordProtection(_keystorePassword.toCharArray()));
			final java.security.cert.Certificate cert = pke.getCertificate();
			final byte[] spki = cert.getPublicKey().getEncoded();

			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			final byte[] hash = digest.digest(spki);
			final String pin = java.util.Base64.getEncoder().encodeToString(hash);
			System.out.println("- HPKP pin for HTTPS: " + pin);
		}
		catch(Exception e){
			err(e);
			System.out.println("Error: Unable to calculate HPKP pin from keystore certificate");
			// Not fatal, we can technically keep going
		}
	}


	////////////////////////////////////////////////
	// ERROR VERTICLE

	private static class ErrorWorkerVerticle extends AbstractVerticle 
	{
		public ErrorWorkerVerticle() throws Exception
		{
		}

		public static void immediate(String payload)
		{
			Vertx vertx = Vertx.vertx();
			final HttpClient httpClient = vertx.createHttpClient(
				new HttpClientOptions().setSsl(API_SSL).setTrustAll(true));
			send( httpClient, payload, true);
			//try { Thread.sleep(4000); } catch(Exception e){}
		}

		private static void send(HttpClient client, String payload, boolean fatal)
		{
			String _leader = "/" + App._address + "/" + App._hostname + "/" + String.valueOf(IVER) + 
				"/" + _strInput + "/" + _strTransform + "/" + _strOutput + "\n";
			String org = "-";
			if( _input != null ) org = Utils.hex( _input.learnedOrgId() );
			client.post(API_PORT, API_HOST, ERR_PATH)
				.handler( response -> {
					// Best effort; it's allowed to fail
					if( fatal ) System.exit(1);
				})
				.setTimeout(10000)
				.putHeader("Content-Type","application/octet-stream")
				.putHeader("Content-Length", String.valueOf( payload.length() +
					_leader.length() + org.length()) )
				.write(org).write(_leader).write( payload ).end();
		}

		@Override
		public void start() throws Exception 
		{
			final HttpClient httpClient = vertx.createHttpClient(
				new HttpClientOptions().setSsl(API_SSL).setTrustAll(true));

			vertx.eventBus().consumer("cti.err", message -> {
				String payload = (String)message.body();
				if( payload != null ){
					send( httpClient, payload, false );
				}
			});
		}
	}

	////////////////////////////////////////////////
	// STATS VERTICLE

	private class StatsWorkerVerticle extends AbstractVerticle 
	{
		private String _leader;
		final HttpClient _client;

		public StatsWorkerVerticle() throws Exception
		{
			_client = App.vertx.createHttpClient(new HttpClientOptions().setSsl(API_SSL).setTrustAll(true));
		}

		@Override
		public void stop()
		{
			send( App.this.counterPayload() );
			try { _stoppingObj.wait(); } catch(Exception e){}
		}

		private boolean _stopping = false;
		private Object _stoppingObj = new Object();

		private void send(byte[] stats_b)
		{
			if( stats_b == null || stats_b.length < 56 ) return;

			try {
				Buffer b = Buffer.buffer(stats_b);
				long[] stats = new long[7];
				stats[0] = b.getLong(0);
				stats[1] = b.getLong(8);
				stats[2] = b.getLong(16);
				stats[3] = b.getLong(24);
				stats[4] = b.getLong(32);
				stats[5] = b.getLong(40);
				stats[6] = b.getLong(48);

				StringBuilder sb = new StringBuilder();
				sb.append(IVER).append("\t");
				sb.append(App._address).append("\t");
				sb.append(App._hostname).append("\t");
				sb.append( Utils.hex(_input.learnedOrgId()) ).append("\t");
				sb.append(_strInput).append("/");
				sb.append(_strTransform).append("/");
				sb.append(_strOutput).append("\t");
				sb.append(stats[0]).append("\t");
				sb.append(stats[1]).append("\t");
				sb.append(stats[2]).append("\t");
				sb.append(stats[3]).append("\t");
				sb.append(stats[4]).append("\t");
				sb.append(stats[5]).append("\t");
				sb.append(stats[6]);

				_client.post(API_PORT, API_HOST, STATS_PATH)
					.handler( response -> {
						// Best effort; it's allowed to fail

						// If this is stopping, then notify we're done
						if( _stopping ) _stoppingObj.notifyAll();
					})
					.setTimeout(10000)
					.putHeader("Content-Type","application/octet-stream")
					.putHeader("Content-Length", String.valueOf(sb.length()))
					.write( sb.toString() ).end();

				System.out.println("Statistics: OK=" + String.valueOf(stats[0]) +
					" ErrInput=" + String.valueOf(stats[1]) + " ErrTransform=" +
					String.valueOf(stats[2]) + " ErrOutput=" + String.valueOf(stats[3]) +
					" ErrOther=" + String.valueOf(stats[4]) + " Dropped=" +
					String.valueOf(stats[5]) + " DroppedData=" + String.valueOf(stats[6]));
			}
			catch(Throwable e){
				App.err(e);
			}
		}

		@Override
		public void start() throws Exception 
		{
			vertx.eventBus().consumer("cti.stats", message -> {
				byte[] stats_b = (byte[])message.body();
				if( App.DEBUG ) System.out.println("- Stats send request");
				send(stats_b);
			});
		}
	}
}
