package com.qx.back.io.ssl;

import java.io.IOException;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;


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
public abstract class SSL_Endpoint {

	public final static int TARGET_PACKET_SIZE = 4096; // 2^12

	private String name;

	private boolean isServerSide;
	
	protected SSL_Phase phase;

	private AsynchronousSocketChannel channel;

	private long timeout;

	private ExecutorService internalExecutor;

	private boolean isVerbose;
	
	private boolean isClosed;

	/**
	 * 
	 * @param name : name of the endpoint
	 * @param isServerSide : server-side flag
	 * @param channel : underlying channel
	 * @param context : underlying SSLContext
	 * @param executor : executor for AIO callback handling
	 * @param timeout : timeout for I/O [seconds]
	 * @param isVerbose : print log
	 */
	public SSL_Endpoint(
			AsynchronousSocketChannel channel,
			ExecutorService executor,
			SSL_EndpointConfig config) {
		super();

		this.channel = channel;
		this.internalExecutor = executor;

		// configuration
		this.name = config.getName();
		this.isServerSide = config.isServerSide();
		this.isVerbose = config.isSSLVerbose();
		this.timeout = config.getTimeout();
		
		phase = SSL_Phase.CREATION;
		isClosed = false;
	}
	
	protected abstract SSL_Inbound getInbound();
	
	protected abstract SSL_Outbound getOutbound();
	
	
	/**
	 * 
	 * @param inbound
	 * @param outbound
	 * @param context
	 */
	public void start(SSLContext context, SSL_Inbound inbound, SSL_Outbound outbound) {
		
		// engine
		SSLEngine engine = createEngine(context, isServerSide);
		getInbound().bind(this, engine, channel, timeout, internalExecutor, isVerbose);
		getOutbound().bind(this, engine, channel, timeout, internalExecutor, isVerbose);
		phase =SSL_Phase.INITIAL_HANDSHAKE;
	}
	
	
	public String getName() {
		return name;
	}





	/**
	 * 
	 */
	public void receive() {
		getInbound().requestUnwrap();
	}

	public void send() {
		getOutbound().requestWrap();
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
		// close inbound side
		getInbound().close();
		
		// close outbound side
		getOutbound().close();
		
		// close channel
		try {
			channel.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		isClosed = true;
	}
	
	public boolean isClosed() {
		return isClosed;
	}
}
