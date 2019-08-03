package com.qx.io.ssl.tests;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;


public abstract class SSL_EndpointUnitTest02 {

	public final static String MESSAGE1 = "Hello Client, I'm Server";
	public final static String MESSAGE2 = "Hi Server, I'm Client";

	public static class Client extends SSL_EndpointUnitTest02 {

		public Client(SSLContext context) throws Exception {
			super(context, "client", MESSAGE2, MESSAGE1);
		}

		@Override
		public void initializeEngine(SSLContext context) {
			/*
			 * Similar to above, but using client mode instead.
			 */
			engine = context.createSSLEngine("client", 80);
			engine.setUseClientMode(true);
		}


	}


	public static class Server extends SSL_EndpointUnitTest02 {

		public Server(SSLContext context) throws Exception {
			super(context, "server", MESSAGE1, MESSAGE2);
		}

		@Override
		public void initializeEngine(SSLContext context) throws Exception {
			/*
			 * Configure the serverEngine to act as a server in the SSL/TLS
			 * handshake.  Also, require SSL client authentication.
			 */
			engine = context.createSSLEngine();
			engine.setUseClientMode(false);
			engine.setNeedClientAuth(true);
		}
	}

	private boolean logging = true;

	private String name;

	public SSLEngine engine;     // server Engine
	public SSLEngineResult result;
	
	private byte[] expectedPayload; 

	// application layer buffers
	public ByteBuffer applicationInput;        // read side of serverEngine
	public ByteBuffer applicationOutput;       // write side of serverEngine
	
	// transport layer buffers
	public ByteBuffer transportInput;	
	public ByteBuffer transportOutput;

	public SSL_EndpointUnitTest02(SSLContext context, String name, 
			String sentPayload,
			String expectedPayload) throws Exception {
		super();

		this.name = name;


		// SSL Engine specific (client/server) setup
		initializeEngine(context);

		/*
		 * We'll assume the buffer sizes are the same
		 * between client and server.
		 */
		SSLSession session = engine.getSession();
		int appBufferMax = session.getApplicationBufferSize();
		int netBufferMax = session.getPacketBufferSize();

		/*
		 * We'll make the input buffers a bit bigger than the max needed
		 * size, so that unwrap()s following a successful data transfer
		 * won't generate BUFFER_OVERFLOWS.
		 *
		 * We'll use a mix of direct and indirect ByteBuffers for
		 * tutorial purposes only.  In reality, only use direct
		 * ByteBuffers when they give a clear performance enhancement.
		 */
		applicationInput = ByteBuffer.allocate(appBufferMax + 1024);

		applicationOutput = ByteBuffer.wrap(sentPayload.getBytes());

		// transportInput is setup by the other side

		transportOutput = ByteBuffer.allocateDirect(netBufferMax);

		this.expectedPayload = expectedPayload.getBytes();
	}



	public void send() throws Exception {
		result = engine.wrap(applicationOutput, transportOutput);
		log2(name+" wrap: ");
		runDelegatedTasks();
	}


	public void receive() throws Exception {
		result = engine.unwrap(transportInput, applicationInput);
		log2(name+"unwrap: ");
		runDelegatedTasks();
	}


	private void runDelegatedTasks() throws Exception {

		/* <delegated-tasks> */

		/*
		 * If the result indicates that we have outstanding tasks to do,
		 * go ahead and run them in this thread.
		 */
		if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
			Runnable runnable;
			while ((runnable = engine.getDelegatedTask()) != null) {
				System.out.println("\trunning delegated task...");
				runnable.run();
			}
			HandshakeStatus hsStatus = engine.getHandshakeStatus();
			if (hsStatus == HandshakeStatus.NEED_TASK) {
				throw new Exception(
						"handshake shouldn't need additional tasks");
			}
			System.out.println("\tnew HandshakeStatus: " + hsStatus);
		}
		/* </delegated-tasks> */

	}

	/**
	 * Using the SSLContext created during object creation,
	 * create/configure the SSLEngines we'll use for this demo.
	 * @throws Exception 
	 */
	public abstract void initializeEngine(SSLContext context) throws Exception;



	public boolean isClosed() {
		return engine.isOutboundDone() && engine.isInboundDone();
	}

	/*
	 * Logging code
	 */
	private static boolean resultOnce = true;

	private void log2(String str) {
		if (!logging) {
			return;
		}
		if (resultOnce) {
			resultOnce = false;
			System.out.println("The format of the SSLEngineResult is: \n" +
					"\t\"getStatus() / getHandshakeStatus()\" +\n" +
					"\t\"bytesConsumed() / bytesProduced()\"\n");
		}
		HandshakeStatus hsStatus = result.getHandshakeStatus();
		System.out.println(name+str +
				", result:"+result.getStatus() + 
				", hand. status:" + hsStatus + ", " +
				", in:"+result.bytesConsumed() + 
				", out:" + result.bytesProduced());
		if (hsStatus == HandshakeStatus.FINISHED) {
			System.out.println("\t...ready for application data");
		}
	}

	/**
	 * After we've transfered all application data between the client
	 * and server, we close the clientEngine's outbound stream.
	 * This generates a close_notify handshake message, which the
	 * server engine receives and responds by closing itself.
	 *
	 * In normal operation, each SSLEngine should call
	 * closeOutbound().  To protect against truncation attacks,
	 * SSLEngine.closeInbound() should be called whenever it has
	 * determined that no more input data will ever be
	 * available (say a closed input stream).
	 */
	public boolean isSent() {

		return !applicationOutput.hasRemaining();
	}

	public boolean isReceived() {
		applicationInput.flip();
		for(int i=0; i<expectedPayload.length; i++) {
			if(applicationInput.get()!=expectedPayload[i]) {
				return false;
			}
		}
		return true;
	}
}
