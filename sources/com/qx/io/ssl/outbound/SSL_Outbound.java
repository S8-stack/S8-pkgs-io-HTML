package com.qx.io.ssl.outbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;

import com.qx.base.reactive.QxIOReactive;
import com.qx.io.ssl.SSL_Endpoint;


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
	public final static int APPLICATION_OUTPUT_STARTING_CAPACITY = 17408;


	public AsynchronousSocketChannel channel;

	public long timeout;

	public ExecutorService internalExecutor;

	public boolean isVerbose;



	/**
	 * Typical required NETWORK_OUTPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_OUTPUT_STARTING_CAPACITY = 17408;


	private AtomicBoolean isRunning;

	public Wrapping wrapping;
	public Pushing pushing;
	public Flushing flushing;
	public Closing closing;
	public RunningDelegates runningTasks;
	public UnwrapRequesting requestUnwrapping;



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
	}
	
	
	public void bind() {
		
		// create modes
		pushing = new Pushing();
		flushing = new Flushing();
		requestUnwrapping = new UnwrapRequesting();
		runningTasks = new RunningDelegates();
		wrapping = new Wrapping();
		closing = new Closing();

		// binding modes
		pushing.bind(this);
		flushing.bind(this);
		requestUnwrapping.bind(this);
		runningTasks.bind(this);
		wrapping.bind(this);
		closing.bind(this);
		
		
		/* 
		 * Left in read mode outside retrieve state. So initialize with nothing to read
		 */
		ByteBuffer applicationBuffer = ByteBuffer.allocate(APPLICATION_OUTPUT_STARTING_CAPACITY);
		applicationBuffer.position(0);
		applicationBuffer.limit(0);
		// left in read mode, empty
		setApplicationBuffer(applicationBuffer);

		/* </buffer> */

		// set parameters
		ByteBuffer networkBuffer = ByteBuffer.allocate(NETWORK_OUTPUT_STARTING_CAPACITY);		
		// left in write mode
		setNetworkBuffer(networkBuffer);
		
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
	protected void run(SSL_OutboundMode.Task task) {
		while(task!=null) {
			task = task.run();
		}
	}


	/**
	 * 
	 */
	public void resume() {
		/* Prevent from double triggering from the exterior */
		if(isRunning.compareAndSet(false, true)) {
			run(wrapping.new Task());
		}
	}


	/**
	 * <p>Available to SSL_OutboundMode ONLY </p>
	 */
	protected void stop() {
		isRunning.set(false);
	}


	/**
	 * Set buffer 
	 * 
	 * @param buffer
	 */
	protected void setNetworkBuffer(ByteBuffer buffer) {
		pushing.setNetworkBuffer(buffer);
		flushing.setNetworkBuffer(buffer);
		wrapping.setNetworkBuffer(buffer);
		closing.setNetworkBuffer(buffer);
	}
	
	protected void setApplicationBuffer(ByteBuffer buffer) {
		wrapping.setApplicationBuffer(buffer);
		closing.setApplicationBuffer(buffer);
	}

}
