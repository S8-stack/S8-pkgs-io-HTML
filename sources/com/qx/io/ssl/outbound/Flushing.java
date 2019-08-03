package com.qx.io.ssl.outbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.TimeUnit;

public class Flushing extends SSL_OutboundMode {

	private AsynchronousSocketChannel channel;

	private long timeout;

	private boolean isVerbose;

	private ByteBuffer networkBuffer;

	private SSL_Outbound outbound;
	
	private String name;

	public Flushing() {
		super();
	}


	/**
	 * 
	 * @author pc
	 *
	 */
	public class Task extends SSL_OutboundMode.Task {

		private SSL_OutboundMode.Task callback;

		public Task(SSL_OutboundMode.Task callback) {
			super();
			this.callback = callback;
		}

		@Override
		public SSL_OutboundMode.Task run() {
			
			if(isVerbose) {
				System.out.println("\t--->"+name+" is flushing... ");
			}

			/* (switch back to read mode) for AIO.write */
			networkBuffer.flip();

			// if there is actually new bytes, send them
			if(networkBuffer.hasRemaining()) {
				try {
					channel.write(networkBuffer, timeout, TimeUnit.SECONDS, null, 
							new CompletionHandler<Integer, Void>() {

						@Override
						public void completed(Integer nBytes, Void attachment) {
							
							boolean isFlushed = !networkBuffer.hasRemaining();

							/* 
							 * Everything might not have been written, 
							 * so compact (and switch to write mode) */
							networkBuffer.compact();


							if(nBytes==-1) {
								if(isVerbose) {
									System.out.println("Failed to flush all remaingin data when closing");
								}
								// end up here
							}
							else if(isFlushed){
								/*
								 *  Once all bytes has been flushed to the network, callback
								 */
								outbound.run(callback);
							}
							
							else {
								// keep flushing until all is gone
								outbound.run(Flushing.Task.this);
								
							}
						}

						@Override
						public void failed(Throwable exc, Void attachment) {
							if(isVerbose) {
								exc.printStackTrace();
							}
						}
					});
				}
				catch (IllegalArgumentException | ReadPendingException |
						NotYetConnectedException | ShutdownChannelGroupException e) {
					if(isVerbose) {
						e.printStackTrace();
					}
					return null;
				}
			}
			return null; // stop here and restart with AIO
		}

	}


	@Override
	public void bind(SSL_Outbound outbound) {
		this.outbound = outbound;
		channel = outbound.channel;
		timeout = outbound.timeout;
		isVerbose = outbound.isVerbose;
		name = outbound.name;
	}
	
	public void setNetworkBuffer(ByteBuffer buffer) {
		networkBuffer = buffer;
	}
	
}
