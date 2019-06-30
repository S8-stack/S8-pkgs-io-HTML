package com.qx.back.io.ssl.inbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;


public class Pulling extends SSL_InboundMode {

	private boolean isVerbose;


	private SSLEngine engine;

	private ByteBuffer networkBuffer;

	private AsynchronousSocketChannel channel;

	private long timeout;

	private SSL_InboundMode unwrapping, closing;

	private AtomicBoolean isReadPending;


	public Pulling(SSL_Inbound inbound) {
		super(inbound);



	}

	@Override
	public void bind() {
		// setup
		this.engine = inbound.engine;
		this.channel = inbound.channel;
		this.networkBuffer = inbound.networkBuffer;
		this.timeout = inbound.timeout;
		this.isVerbose = inbound.isVerbose;

		// other states
		this.unwrapping = inbound.unwrapping;
		this.closing = inbound.closing;
	}


	@Override
	public SSL_InboundMode run() {

		/*
		 * Can start directly (protected by SSL_Inbound isRunning atomic boolean)
		 */

		try {

			/*
			 * prepare for reception. From javadoc: "this method after writing data from a
			 * buffer in case the write was incomplete" -> is always the case: 1) Underflow
			 * : incomplete packet 2) OK: successfully read this packet, but reading next
			 * packet is required
			 */
			/* network input buffer -> WRITE */
			networkBuffer.compact();		

			channel.read(networkBuffer, timeout, TimeUnit.SECONDS, null, 
					new CompletionHandler<Integer, Void>() {

				@Override
				public void completed(Integer nBytes, Void attachment) {

					// unlock possibility to read
					isReadPending.set(false);

					/* network input buffer -> READ */
					networkBuffer.flip();

					if(nBytes==-1) {
						/* SSLEngine JAVA documentation: 
						 * If for some reason the peer closes the communication link without sending the
						 * proper SSL/TLS closure message, the application can detect the end-of-stream
						 * and can signal the engine via closeInbound() that there will no more inbound
						 * messages to process
						 */
						try {
							engine.closeInbound();
						} 
						catch (SSLException e) {
							e.printStackTrace();
						}
						inbound.run(closing);
					}
					else if(nBytes>0){
						// everything is fine, so resume unwrapping
						inbound.run(unwrapping);
					}		
					else { // no new bytes, so retry pulling
						inbound.run(Pulling.this);
					}
				}

				@Override
				public void failed(Throwable e, Void attachment) {
					if(isVerbose) {
						e.printStackTrace();
					}
					// initiate closing procedure
					inbound.run(closing);
				}
			});	
		}
		catch (IllegalArgumentException |
				ReadPendingException |
				NotYetConnectedException |
				ShutdownChannelGroupException e) {

			if(isVerbose) {
				e.printStackTrace();
			}
			inbound.run(closing);
		}

		// end of the road, to be continued when AIO-CompletionHandler completes...
		return null;

	}

}
