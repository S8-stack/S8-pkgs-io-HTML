package com.qx.back.io.ssl.inbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;


class Pulling extends SSL_InboundMode {


	private SSLEngine engine;

	private ByteBuffer networkBuffer;

	private AsynchronousSocketChannel channel;

	private long timeout;
	
	private SSL_Inbound inbound;

	private Unwrapping unwrapping;
	private Closing closing;

	private String name;
	private boolean isVerbose;

	public Pulling() {
		super();
	}

	@Override
	public void bind(SSL_Inbound inbound) {
		
		this.name = inbound.name;
		this.inbound = inbound;
		
		// setup
		this.engine = inbound.engine;
		this.channel = inbound.channel;
		this.timeout = inbound.timeout;

		// other states
		this.unwrapping = inbound.unwrapping;
		this.closing = inbound.closing;
		
		isVerbose = inbound.isVerbose;
	}

	
	public class Task extends SSL_InboundMode.Task {
	
		public Task() {
			super();
		}
		
		@Override
		public SSL_InboundMode.Task run() {

			/* Can start directly (protected by SSL_Inbound isRunning atomic boolean) */
			if(isVerbose) {
				System.out.println("\t--->"+name+" is pulling... ");
			}

			try {

				/* 
				 * Prepare for reception. From javadoc: "this method after writing data from a
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
							inbound.run(closing.new Task());
						}
						else if(nBytes>0){
							// everything is fine, so resume unwrapping
							inbound.run(unwrapping.new Task());
						}		
						else { // no new bytes, so retry pulling
							inbound.run(Pulling.Task.this);
						}
					}

					@Override
					public void failed(Throwable e, Void attachment) {
						if(isVerbose) {
							e.printStackTrace();
						}
						// initiate closing procedure
						inbound.run(closing.new Task());
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
				inbound.run(closing.new Task());
			}

			// end of the road, to be continued when AIO-CompletionHandler completes...
			return null;

		}
		
	}

	public void setNetworkBuffer(ByteBuffer buffer) {
		networkBuffer = buffer;
	}
	

}
