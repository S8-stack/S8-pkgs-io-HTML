package com.qx.back.io.ssl.outbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;

import com.qx.back.base.reactive.QxIOReactive;
import com.qx.back.io.ssl.SSL_Endpoint;


/**
 * <p>
 * SSL_Outbound
 * </p>
 * 
 * @author pc
 *
 */
public class SSL_Outbound {

	public QxIOReactive sender;

	public String name;

	public SSL_Endpoint endpoint;

	public SSLEngine engine;

	/**
	 * Typical required APPLICATION_OUTPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408.
	 * Replace by 2^15 (for beauty purposes)
	 */
	public final static int APPLICATION_OUTPUT_STARTING_CAPACITY = 32768;

	public ByteBuffer applicationBuffer;


	public AsynchronousSocketChannel channel;

	public long timeout;

	public ExecutorService internalExecutor;

	public boolean isVerbose;



	/**
	 * Typical required NETWORK_OUTPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_OUTPUT_STARTING_CAPACITY = 32768;


	protected ByteBuffer networkBuffer;


	private AtomicBoolean isRunning;

	public SSL_OutboundMode wrapping, pushing, flushing, closing, runningTasks, requestUnwrapping;



	/**
	 * 
	 * @param channel
	 */
	public SSL_Outbound(QxIOReactive sender, 
			SSL_Endpoint endpoint, 
			SSLEngine engine, 
			AsynchronousSocketChannel channel, 
			long timeout, 
			ExecutorService internalExecutor, 
			boolean isVerbose) {
		super();

		this.sender = sender;

		// bind 0
		this.endpoint = endpoint;
		this.engine = engine;
		this.channel = channel;
		this.timeout = timeout;
		this.internalExecutor = internalExecutor;
		this.isVerbose = isVerbose;		


		name = endpoint.getName()+".outbound";

		/* <buffers> */


		/* 
		 * Left in read mode outside retrieve state. So initialize with nothing to read
		 */
		applicationBuffer = ByteBuffer.allocate(APPLICATION_OUTPUT_STARTING_CAPACITY);
		applicationBuffer.position(0);
		applicationBuffer.limit(0);

		/* </buffer> */



		// set parameters


		networkBuffer = ByteBuffer.allocate(NETWORK_OUTPUT_STARTING_CAPACITY);		
		networkBuffer.position(0);
		networkBuffer.limit(0);

		// initial setup
		isRunning = new AtomicBoolean(false);

	}

	/**
	 * <p>Available to SSL_OutboundMode ONLY </p>
	 * <p>
	 * Not that inbound is by default ALWAYS running, with the exception of the pause for
	 * requesting Wrapping on the outbound (that in turn will resume inbound).
	 * </p>
	 * <p>
	 * If during an re-handshaking, start is called again, it will have no effect since 
	 * inbound will already be running
	 * </p>
	 * @param mode
	 */
	protected void run(SSL_OutboundMode mode) {
		while(mode!=null) {
			mode = mode.run();
		}
	}


	/**
	 * 
	 */
	public void resume() {
		/* Prevent from double triggering from the exterior */
		if(isRunning.compareAndSet(false, true)) {
			run(wrapping);
		}
	}

	
	/**
	 * <p>Available to SSL_OutboundMode ONLY </p>
	 */
	protected void stop() {
		isRunning.set(true);
	}
	
	
	

}
