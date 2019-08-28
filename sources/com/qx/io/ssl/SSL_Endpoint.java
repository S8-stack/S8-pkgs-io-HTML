package com.qx.io.ssl;

import java.io.IOException;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;

import com.qx.io.ssl.inbound.SSL_Inbound;
import com.qx.io.ssl.outbound.SSL_Outbound;
import com.qx.io.web.rx.RxEndpoint;


/**
 *
 * 
 * 
 * @author pc
 */
public abstract class SSL_Endpoint extends RxEndpoint {


	public final static int TARGET_PACKET_SIZE = 4096; // 2^12

	//private RxWebEndpoint base;

	private String name;

	private boolean isServerSide;

	private SSL_Phase phase;

	private SSLEngine engine;

	private boolean isVerbose;


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
	 * @throws IOException 
	 */
	public SSL_Endpoint(
			Selector selector, 
			SocketChannel socketChannel,
			String name,
			SSLContext context,
			boolean isServerSide,
			boolean isVerbose) throws IOException {

		super(selector, socketChannel);


		this.name = name;


		// configuration
		this.isServerSide = isServerSide;
		this.isVerbose = isVerbose;

		phase = SSL_Phase.CREATION;
		isClosed = false;

		// engine
		engine = createEngine(context, isServerSide);

		phase =SSL_Phase.INITIAL_HANDSHAKE;

	}

	@Override
	public abstract SSL_Inbound getInbound();

	@Override
	public abstract SSL_Outbound getOutbound();


	public void SSL_bind() {

		// sub-bind
		rxBind();

		getInbound().SSL_bind(this, engine);
		getOutbound().SSL_bind(this, engine);
	}


	public String getName() {
		return name;
	}

	
	/**
	 * <p>
	 * Start the endpoint
	 * </p>
	 * <p>
	 * This choice determines who begins the handshaking process as well as which
	 * type of messages should be sent by each party. The method
	 * setUseClientMode(boolean) configures the mode. Once the initial handshaking
	 * has started, an SSLEngine can not switch between client and server modes,
	 * even when performing renegotiations.
	 * </p>
	 */
	public void start() {
		if(isServerSide) {
			receive();
		}
		else {
			send();
		}
	}

	public void resume() {
		receive();	
		send();
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

	@Override
	public void close() {
		super.close();
		isClosed = true;
	}


	public boolean isClosed() {
		return isClosed;
	}


}
