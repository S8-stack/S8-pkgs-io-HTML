package com.qx.back.io.ssl;

import java.io.IOException;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;

import com.qx.back.base.reactive.QxIOReactive;
import com.qx.back.io.ssl.inbound.SSL_Inbound;
import com.qx.back.io.ssl.outbound.SSL_Outbound;


/**
 *
 * 
 * 
 * @author pc
 */
public class SSL_Endpoint {

	public final static int TARGET_PACKET_SIZE = 4096; // 2^12

	private String name;

	private boolean isServerSide;

	protected SSL_Phase phase;
	
	public SSLEngine engine;

	public AsynchronousSocketChannel channel;

	public ExecutorService internalExecutor;

	public boolean isVerbose;

	public SSL_Inbound inbound;

	public SSL_Outbound outbound;

	public boolean isClosed;
	
	

	/**
	 * 
	 * @param name name (for SSL debugging when verbose)
	 * @param receiver QxIOReactive
	 * @param sender QxIOReactive
	 * @param context
	 * @param channel 
	 * @param timeout
	 * @param executor
	 * @param isServerSide
	 * @param isVerbose
	 */
	public SSL_Endpoint(
			String name,
			QxIOReactive receiver,
			QxIOReactive sender,
			SSLContext context,
			AsynchronousSocketChannel channel,
			long timeout,
			ExecutorService executor,
			boolean isServerSide,
			boolean isVerbose) {
		super();
		this.name = name;
		
		this.channel = channel;
		this.internalExecutor = executor;

		// configuration
		this.isServerSide = isServerSide;
		this.isVerbose = isVerbose;

		phase = SSL_Phase.CREATION;
		isClosed = false;

		// engine
		engine = createEngine(context, isServerSide);

		// start inbound
		inbound = new SSL_Inbound(receiver, this, engine, 
				channel, timeout, internalExecutor, isVerbose);

		// start outbound
		outbound = new SSL_Outbound(sender, this, engine, 
				channel, timeout, internalExecutor, isVerbose);

		phase =SSL_Phase.INITIAL_HANDSHAKE;
		
		inbound.bind();
		outbound.bind();
	}



	public String getName() {
		return name;
	}

	public void start() {
		/*
		 * This choice determines who begins the handshaking process as well as which
		 * type of messages should be sent by each party. The method
		 * setUseClientMode(boolean) configures the mode. Once the initial handshaking
		 * has started, an SSLEngine can not switch between client and server modes,
		 * even when performing renegotiations.
		 */
		if(isServerSide) {
			inbound.resume();		
		}
		else {
			outbound.resume();	
		}
	}

	public void resume() {
		inbound.resume();	
		outbound.resume();
	}


	public static SSLEngine createEngine(SSLContext context, boolean isServerSide) {
		/* <init_SSLEngine> */

		SSLEngine engine = context.createSSLEngine();

		if(isServerSide) {
			/*
			 * Configure the serverEngine to act as a server in the SSL/TLS
			 * handshake.  Also, require SSL client authentication.
			 */
			engine.setUseClientMode(false);

			// always require client authentication, as a secured implemenatation
			//engine.setNeedClientAuth(true);

		}
		else { // client side
			/*
			 * Similar to above, but using client mode instead.
			 */
			engine.setUseClientMode(true);
		}

		SSLParameters parameters = engine.getSSLParameters();
		parameters.setMaximumPacketSize(TARGET_PACKET_SIZE);
		parameters.setApplicationProtocols(new String[]{"h2"});

		engine.setSSLParameters(parameters);


		return engine;
	}


	public void onResult(SSLEngineResult result) {
		phase = phase.transition(result);
	}


	/**
	 * 
	 * @return
	 */
	public boolean isHandshaking() {
		return phase == SSL_Phase.INITIAL_HANDSHAKE || phase == SSL_Phase.REHANDSHAKING;
	}


	public boolean isVerbose() {
		return isVerbose;
	}

	public boolean isServerSide() {
		return isServerSide;
	}

	public void close() {
		isClosed = true;
	}

	public void shutDown() {

		// close channel
		try {
			channel.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean isClosed() {
		return isClosed;
	}
	
	
}
