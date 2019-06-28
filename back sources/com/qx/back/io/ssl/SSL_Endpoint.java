package com.qx.back.io.ssl;

import java.io.IOException;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;

import com.qx.back.base.reactive.QxIOReactive;


/**
 *
 * <p>
 * Endpoint implementing an SSLAsynchronousSocketChannel
 * </p>
 * <p>
 * <pre>
 *    
 * 				 	
 *              / \
 *             /   \
 *            /  |  \
 *           /   |   \
 *          /         \
 *         /     *     \
 *         -------------
 * 
 * </pre>
 * <p>
 * DO NOT ENGAGE in channel.write(...) directly since JAVA implementation can use a dirty hack.
 * Internal InvokeDirect within AsynchronousSocketChannel.write method can almost randomly
 * break the asynchronous nature of the call and therefore produce callstacking of a DIRECT write 
 * (general idea behind is that if write can be done directly, better to save thread).
 * </p>
 * <p>
 * In any case, you cannot trust write to cut callstack and must rely on another mechanism. The one 
 * implemented here is using an internal ExecutorService.
 * </p>
 * 
 * @author pc
 */
public class SSL_Endpoint {

	public final static int TARGET_PACKET_SIZE = 4096; // 2^12

	private String name;

	private boolean isServerSide;

	protected SSL_Phase phase;

	private AsynchronousSocketChannel channel;

	private ExecutorService internalExecutor;

	private boolean isVerbose;

	private boolean isClosed;

	private SSL_Inbound inbound;

	private SSL_Outbound outbound;

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
		SSLEngine engine = createEngine(context, isServerSide);

		// start inbound
		inbound = new SSL_Inbound(receiver, this, engine, 
				channel, timeout, internalExecutor, isVerbose);

		// start outbound
		outbound = new SSL_Outbound(sender, this, engine, 
				channel, timeout, internalExecutor, isVerbose);

		phase =SSL_Phase.INITIAL_HANDSHAKE;
	}



	public String getName() {
		return name;
	}


	public void resumeSending() {
		outbound.requestWrap();
	}

	/**
	 * 
	 */
	public void unwrap() {
		inbound.requestUnwrap();
	}

	public void wrap() {
		outbound.requestWrap();
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
