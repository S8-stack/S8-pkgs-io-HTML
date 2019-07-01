package com.qx.back.io.ssl.inbound;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;

import com.qx.back.base.reactive.QxIOReactive;
import com.qx.back.io.ssl.SSL_Endpoint;


/**
 * Inbound part of the SSL_Endpoint
 * 
 * @author pc
 *
 */
public class SSL_Inbound {



	public String name;

	/**
	 * Typical required APPLICATION_INPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int APPLICATION_INPUT_STARTING_CAPACITY = 17408;


	/**
	 * Typical required NETWORK_INPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_INPUT_STARTING_CAPACITY = 17408;


	protected SSL_Endpoint endpoint;

	protected SSLEngine engine;

	public AsynchronousSocketChannel channel;

	/**
	 * <h1>First Key building-up method</h1>
	 * <p> Based on the "don't call us, we'll call you" principle. 
	 * Namely, use this class by overriding this method and supply 
	 * bytes when required. You cannot force immediate reading
	 * since PENDING_REDAING can be on progress (consequence of 
	 * asynchronous nature of this SSLEndPoint).
	 * </p>
	 * <p><b>/!\ FULL DRAIN: Upon this method call, ALL bytes MUST be 
	 * consumed</b></p>
	 * <p>Thread safety is ensured as long as <code>resumeReceiving()</code> 
	 * is not called in the body of this class implementation</p>
	 * 
	 * @param buffer the source buffer of the bytes to be read by any
	 * class subclass (Already flipped, ready for reading).
	 * @return a flag indicating if another call is required (remember 
	 * that you <b>CANNOT chain reception operation by calling <code>
	 * resumeReceiving()</code></b>in the method implementation.
	 */
	public QxIOReactive receiver;

	public long timeout;

	public ExecutorService internalExecutor;


	public boolean isVerbose;


	public AtomicBoolean isRunning;




	/**
	 * pre-defined modes
	 */
	public Pulling pulling;
	public RequestWrapping requestWrapping;
	public RunningTask delegatesRunning;
	public Unwrapping unwrapping;
	public Closing closing;


	/**
	 * 
	 * @param channel
	 */
	public SSL_Inbound(
			QxIOReactive receiver,
			SSL_Endpoint endpoint, 
			SSLEngine engine, 
			AsynchronousSocketChannel channel,
			long timeout,
			ExecutorService internalExecutor,
			boolean isVerbose) {
		super();


		// bind 0
		this.receiver = receiver;
		this.endpoint = endpoint;
		this.engine = engine;
		this.channel = channel;
		this.timeout = timeout;
		this.internalExecutor = internalExecutor;
		this.isVerbose = isVerbose;		

		name = endpoint.getName() + ".inbound";


		// create modes
		pulling = new Pulling();
		requestWrapping = new RequestWrapping();
		delegatesRunning = new RunningTask();
		unwrapping = new Unwrapping();
		closing = new Closing();

		// binding modes
		pulling.bind(this);
		requestWrapping.bind(this);
		delegatesRunning.bind(this);
		unwrapping.bind(this);
		closing.bind(this);


		/* <buffers> */

		ByteBuffer applicationBuffer = ByteBuffer.allocate(APPLICATION_INPUT_STARTING_CAPACITY);
		setApplicationBuffer(applicationBuffer);
		// left in write mode

		ByteBuffer networkBuffer = ByteBuffer.allocate(NETWORK_INPUT_STARTING_CAPACITY);
		networkBuffer.flip(); // left in read mode
		setNetworkBuffer(networkBuffer);

		/* </buffer> */



		isRunning = new AtomicBoolean(false);


	}


	public void resume() {
		if(isRunning.compareAndSet(false, true)) {
			run(unwrapping.new Task());	
		}
	}


	/**
	 * (Available to SSL_InboundMode ONLY)
	 * 
	 */
	protected void stop() {
		isRunning.set(false);
	}

	/**
	 * <p>
	 * (Available to SSL_InboundMode ONLY)
	 * </p>
	 * <p>
	 * Not that inbound is by default ALWAYS running, with the exception of the pause for
	 * requesting Wrapping on the outbound (that in turn will resume inbound).
	 * </p>
	 * <p>
	 * If during an re-handshaking, start is called again, it will have no effect since 
	 * inbound will already be running
	 * </p>
	 * @param task
	 */
	protected void run(SSL_InboundMode.Task task) {
		while(task!=null) {
			task = task.run();
		}
	}



	protected void setNetworkBuffer(ByteBuffer buffer) {
		pulling.setNetworkBuffer(buffer);
		unwrapping.setNetworkBuffer(buffer);
	}


	public void setApplicationBuffer(ByteBuffer buffer) {
		unwrapping.setApplicationBuffer(buffer);
	}


}
