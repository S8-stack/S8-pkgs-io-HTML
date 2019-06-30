package com.qx.back.io.ssl.outbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.TimeUnit;

import com.qx.back.io.ssl.SSL_Endpoint;

public class Pushing extends SSL_OutboundMode {

	private SSL_Endpoint endpoint;

	private AsynchronousSocketChannel channel;

	private long timeout;

	private boolean isVerbose;

	private ByteBuffer networkBuffer;

	private SSL_OutboundMode wrapping, closing;

	public Pushing(SSL_Outbound outbound) {
		super(outbound);
	}

	@Override
	public void bind() {

		endpoint = outbound.endpoint;
		channel = outbound.channel;
		timeout = outbound.timeout;
		isVerbose = outbound.isVerbose;

		// buffers
		networkBuffer = outbound.networkBuffer;

		// modes
		wrapping = outbound.wrapping;
		closing = outbound.closing;
	}

	@Override
	public SSL_OutboundMode run() {

		/* (switch back to read mode) for AIO.write */
		networkBuffer.flip();

		try {
			channel.write(networkBuffer, timeout, TimeUnit.SECONDS, null, 
					new CompletionHandler<Integer, Void>() {

				@Override
				public void completed(Integer nBytes, Void attachment) {

					/* 
					 * Everything might not have been written, 
					 * so compact (and switch to write mode) */
					networkBuffer.compact();


					if(nBytes==-1) {
						endpoint.isClosed = true;
						outbound.run(closing);
					}
					/*
					 * Even if nothing has been written, we'll add so new bytes before retrying
					 */
					else {
						outbound.run(wrapping);
					}
				}

				@Override
				public void failed(Throwable exc, Void attachment) {
					if(isVerbose) {
						exc.printStackTrace();
					}
					endpoint.isClosed = true;
					outbound.run(closing);
				}
			});
		}
		catch (IllegalArgumentException | ReadPendingException |
				NotYetConnectedException | ShutdownChannelGroupException e) {
			if(isVerbose) {
				e.printStackTrace();
			}
			endpoint.isClosed = true;
			outbound.run(closing);
		}

		return null; // stop here and resume by AIO callback
	}
}
