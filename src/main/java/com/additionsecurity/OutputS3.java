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

import io.vertx.core.*;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.*;
import io.vertx.core.http.*;

import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.lang.Exception;
import java.lang.StringBuilder;
import java.io.File;
import java.nio.charset.Charset;

import java.text.DateFormat;
import java.util.Date;
import java.util.UUID;

import com.perceptus.supers3t.*;

import com.additionsecurity.ICTIOutput.ICTIOutputException;

class OutputS3 implements ICTIOutput {

	private static final String DESC = "S3";

	private ICTITransform _transform;
	private EventBus _eb;

	private String _endpoint;
	private String _accessKey;
	private String _secretKey;
	private String _bucket;
	private static String _ext;
	private static Buffer _header;

	private int _maxMemory;
	private long _interval;

	public OutputS3(Properties prop, ICTITransform transform) throws Exception
	{
		// Verify transform compatibility
		if( transform == null ) throw new Exception("transform");
		_transform = transform;
		_ext = transform.extension();
		final String header = transform.header();
		if( header != null ){
			_header = Buffer.buffer( header );
			_header.appendByte( (byte)0x0a );
		}

		// Local configuration
		String v = prop.getProperty("output.s3.endpoint","s3.amazonaws.com");
		_endpoint = v;

		v = prop.getProperty("output.s3.bucket", null);
		if( v == null ) throw new Exception("output.s3.bucket");
		_bucket = v;

		v = prop.getProperty("output.s3.access_key", null);
		if( v == null ) throw new Exception("output.s3.access_key");
		_accessKey = v;

		v = prop.getProperty("output.s3.secret_key", null);
		if( v == null ) throw new Exception("output.s3.secret_key");
		_secretKey = v;

		_maxMemory = Integer.parseInt(prop.getProperty("output.s3.memory_max",
			"8388608")); // Default is 8MB

		_interval = Long.parseLong(prop.getProperty("output.s3.interval",
			"300")); // Default is 5 mins/300 seconds
		_interval *= 1000; // convert to ms

		// Configure our worker verticle
		_eb = App.vertx.eventBus();
		DeploymentOptions options = new DeploymentOptions().setWorker(true);
		MsgWorkerVerticle verticle = new MsgWorkerVerticle(_endpoint, _bucket, 
			_accessKey, _secretKey, _maxMemory, _interval);
		App.vertx.deployVerticle(verticle, options, res-> {
			if( !res.succeeded() ){
				System.out.println("ERROR: S3 Worker Startup Failed");
				System.exit(1);
			}
		});

	}

	public String description()
	{
		StringBuilder sb = new StringBuilder();
		sb.append(DESC).append("; memory_max=").append(_maxMemory);
		sb.append("; interval=").append(_interval/1000);
		return sb.toString();
	}

	public void nowTick(long ts)
	{
		// NO-OP
	}

	public void output(byte[][] datas) throws ICTIOutputException
	{
		try {
			for( int i=0; i<datas.length; i++){
				if( datas[i] == null ) continue;
				_eb.send("cti.s3", datas[i]);
			}
		}
		catch(Exception e){
			throw new ICTIOutputException("write",e);
		}
	}

	private static class BufferWrapper
	{
		public static Buffer b;
	}

	private static class AsyncFileWrapper
	{
		public static String p;
		public static AsyncFile f;
	}

	private static class MsgWorkerVerticle extends AbstractVerticle 
	{
		private S3Client _client;
		private String _bucket;
		private int _bufferSize;
		private AtomicInteger _counter = new AtomicInteger(1);
		private String _prefix = UUID.randomUUID().toString() + ".";

		private AsyncFileWrapper _cacheFile;
		private OpenOptions _openOpts;
		private long _intervalMs;
		private long _timeout = 10000;

		public MsgWorkerVerticle( String endpoint, String bucket, String key, 
			String secret, int maxMemory, long interval) throws Exception
		{
			_client = new S3Client(key,secret,endpoint);
			_bucket = bucket;
			_bufferSize = maxMemory;
			_intervalMs = interval;

			_cacheFile = new AsyncFileWrapper();

			// Open the data safety file
			_openOpts = new OpenOptions().setCreate(true).setWrite(true).setTruncateExisting(true);
			_cacheFile.p = File.createTempFile("cache", "."+_ext).getAbsolutePath();
			_cacheFile.f = App.vertx.fileSystem().openBlocking( _cacheFile.p, _openOpts );

			// Write the header to the safety file, if warranted
			if( _header != null ) _cacheFile.f.write( _header );

			// Set our periodic flush timer
			App.vertx.setPeriodic( _intervalMs, id-> {
				//System.out.println("+ S3 flush timer");
				App.vertx.eventBus().send("cti.s3", null);
			});

			// TODO do a test upload ?
		}

		private int s3_put(String objectName, Buffer buffer_to_send)
		{
			// used to track status and as a lock
			final AtomicInteger responseCode = new AtomicInteger(-1);

			// send the prior buffer
			synchronized(responseCode) {
				// Do the async put
				_client.put( _bucket, objectName, buffer_to_send,
					new Handler<HttpClientResponse>(){
						@Override
						public void handle(HttpClientResponse event){
							synchronized(responseCode){
								responseCode.set(event.statusCode());
								responseCode.notify();
							}
						}
					});

				// Time-bounded wait for completion
				try {
					responseCode.wait( _timeout );
				} catch(InterruptedException e){
					// Timed out
					System.out.println("Warning: S3 put timeout");
					App.err(e);
				}
			}

			return responseCode.intValue();
		}


		@Override
		public void start() throws Exception 
		{
			// Allocate a first working buffer
			final BufferWrapper mem_buffer = new BufferWrapper();
			mem_buffer.b = Buffer.buffer( _bufferSize );

			// Add the header, if warranted
			if( _header != null ) mem_buffer.b.appendBuffer( _header );
			final int header_sz = mem_buffer.b.length();

			// Our flush time tracker
			final AtomicLong _flushTime = new AtomicLong(System.currentTimeMillis());

			vertx.eventBus().consumer("cti.s3", message -> {

				// Process the payload
				byte[] payload = (byte[])message.body();
				if( payload != null && payload.length > 0 ){
					//if( App.DEBUG ) System.out.println("+ Processing message");

					final Buffer b = Buffer.buffer(payload);
					b.appendByte( (byte)0x0a);

					// Save the payload immediately to our memory buffer
					//mem_buffer.b.appendBytes(payload);
					//mem_buffer.b.appendByte('\n');
					mem_buffer.b.appendBuffer( b );

					// Write the payload to our safety cache; it's best-effort
					_cacheFile.f.write( b );

					// Check if we hit any thresholds
					if( mem_buffer.b.length() < _bufferSize ){
						//System.out.println("+ Batch is small, done");
						// Still batching, go on to the next
						return;
					}
				}

				// If we get here, we got a null/empty payload, or our buffer
				// is past max.  Either way, let's run our flush logic.

				// If there is nothign to flush, we're done; note we don't
				// count the header
				if( mem_buffer.b.length() <= header_sz ) {
					//System.out.println("+ No data to flush, done");
					return;
				}

				// If it's a timer trigger, check if it's too recent
				if( payload == null ){
					// Only flush if we haven't flushed in the interval
					if( (_flushTime.get() + _intervalMs) > System.currentTimeMillis() ){
						if( App.DEBUG ) System.out.println("+ Flush timer too soon");
						return; // Too soon
					}
				}

				// We need to do the flush
				if( App.DEBUG ) System.out.println("+ Flushing to S3");

				// roll the buffer
				final Buffer buffer_to_send = mem_buffer.b;
				mem_buffer.b = Buffer.buffer( _bufferSize );
				// Add the header, if warranted
				if( _header != null ) mem_buffer.b.appendBuffer( _header );

				// We need a new unique name for this file object in S3
				String objectName = _prefix + String.valueOf( _counter.incrementAndGet() ) +
					"."+_ext;

				// Do the upload
				int responseCode = s3_put( objectName, buffer_to_send );

				// We need to close our safety file regardless
				_cacheFile.f.close();
				final String prevFile = _cacheFile.p;

				// Create a fresh new file
				try {
					_cacheFile.p = File.createTempFile("cache", "."+_ext).getAbsolutePath();
					_cacheFile.f = App.vertx.fileSystem().openBlocking(_cacheFile.p, _openOpts);
					// Write the header to the safety file, if warranted
					if( _header != null ) _cacheFile.f.write( _header );

				} catch(Exception e) {
					App.err(e);
					System.out.println("Error: Internal integrity failure");
					System.exit(1);
				}

				// Check for success
				if( responseCode != 200 ){
					System.out.println("Error: sending to S3");
					// Everything is stored in the safety file; we won't delete it
					System.out.println("- Backup file: " + prevFile);

				} else {
					if( App.DEBUG ) System.out.println("+ Successfully sent to S3");
					// Successfully uploaded; we can delete the old safety file
					new File(prevFile).delete();

				}

				// Update our flush timer
				_flushTime.set(System.currentTimeMillis());
			});
		}
	}
}
