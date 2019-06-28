package com.qx.back.io.ssl;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * Inbound part of the SSL_Endpoint
 * 
 * @author pc
 *
 */
public abstract class SSL_Inbound {

	private String name;

	/**
	 * Typical required APPLICATION_INPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int APPLICATION_INPUT_STARTING_CAPACITY = 17408;

	/**
	 * always maintained cleared
	 */
	private ByteBuffer applicationBuffer;

	/**
	 * Typical required NETWORK_INPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_INPUT_STARTING_CAPACITY = 17408;


	protected SSL_Endpoint endpoint;

	protected SSLEngine engine;

	private AsynchronousSocketChannel channel;

	private long timeout;

	private ExecutorService internalExecutor;

	protected ByteBuffer networkBuffer;

	
	private boolean isClosed;
	
	/**
	 * Locking mechanism for protection of pending reading.
	 */
	private AtomicBoolean isReadPending;

	/**
	 * Another unwrap request has been notified while <code>isRunning</code>. Flag
	 * allows to keep track of notification
	 */
	private boolean isUnwrapRequested = false;

	private boolean isVerbose;

	/**
	 * 
	 * @param channel
	 */
	public SSL_Inbound() {
		super();
		isClosed = false;
	}


	protected void bind(
			SSL_Endpoint endpoint, 
			SSLEngine engine, 
			AsynchronousSocketChannel channel,
			long timeout,
			ExecutorService internalExecutor,
			boolean isVerbose) {

		// bind 0
		this.endpoint = endpoint;
		this.engine = engine;
		this.channel = channel;
		this.timeout = timeout;
		this.internalExecutor = internalExecutor;
		this.isVerbose = isVerbose;		

		name = endpoint.getName() + ".inbound";

		applicationBuffer = ByteBuffer.allocate(APPLICATION_INPUT_STARTING_CAPACITY);

		/* < > */

		/* <buffers> */
		networkBuffer = ByteBuffer.allocate(NETWORK_INPUT_STARTING_CAPACITY);

		isReadPending = new AtomicBoolean(false);
		/* </buffer> */	
	}


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
	public abstract boolean onReceived(ByteBuffer buffer);



	/**
	 * Notify SSL_Inbound that unwrap is required
	 */
	public void requestUnwrap() {
		if(!isClosed) {
			/* not yet running, so start immediately */
			if(isReadPending.compareAndSet(false, true)) {
				isReadPending.set(true);
				unwrap();
			}
			/* already running, so keep record of requirement */
			else {
				isUnwrapRequested = true;
			}	
		}
	}

	/**
	 * Trigger reception Not thread-safe. MUST be protected by testing isRunning
	 * atomic boolean.
	 */
	private void unwrap() {

		/* network input buffer -> READ */
		networkBuffer.flip();

		boolean needMoreNetworkBytes = unsafeUnwrap();

		/*
		 * prepare for reception. From javadoc: "this method after writing data from a
		 * buffer in case the write was incomplete" -> is always the case: 1) Underflow
		 * : incomplete packet 2) OK: successfully read this packet, but reading next
		 * packet is required
		 */
		/* network input buffer -> WRITE */
		networkBuffer.compact();		


		if(needMoreNetworkBytes) {
			try {
				channel.read(networkBuffer, timeout, TimeUnit.SECONDS, null, new CompletionHandler<Integer, Void>() {

					@Override
					public void completed(Integer nBytes, Void attachment) {
						if(nBytes==-1) {
							close();
						}
						else if(!isClosed){
							try{
								internalExecutor.submit(new Runnable() {
									public @Override void run() {
										unwrap();
									}
								});
							}
							catch (RejectedExecutionException | NullPointerException e) {
								if(isVerbose) {
									e.printStackTrace();
								}
								close();
							}
						}					
					}

					@Override
					public void failed(Throwable e, Void attachment) {
						if(isVerbose) {
							e.printStackTrace();
						}
						close();
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
				close();
			}

			// end of the road, to be continued when AIO-CompletionHandler completes...
		}
		/*
		 * do not need more bytes, but need another unwrap (more bytes may have been
		 * made available in the meantime), that may in turn request more bytes...
		 */
		else if(isUnwrapRequested) {
			isUnwrapRequested = false;
			unwrap();
		}
		// stop reading
		else {
			isReadPending.set(false);
		}
	};



	/**
	 * Unwrap is always triggered by safer <code>unwrap()</code>, so always "safe" from
	 * the <code>PendingRead</code>.
	 * 
	 * @return a flag indicating if need more bytes from network
	 */
	private boolean unsafeUnwrap() {
		try {
			SSLEngineResult unwrapResult;

			int DEBUG_count = 0;
			while(!isClosed) {

				if(isVerbose) {
					System.out.println("\t--->"+name+" is unwrapping... "+DEBUG_count);
					DEBUG_count++;
				}

				/* unwrap */
				unwrapResult = engine.unwrap(networkBuffer, applicationBuffer);

				if(isVerbose) {
					System.out.println(name+": "+unwrapResult);
				}

				/*
				 * update phase based on unwrapping result
				 */
				endpoint.onResult(unwrapResult);

				switch(unwrapResult.getHandshakeStatus()) {

				/*
				 * (Only active while HANDSHAKING)
				 * If the result indicates that we have outstanding tasks to do, go ahead and
				 * run them in this thread.
				 */
				case NEED_TASK:
					/*
					 * Ignore result status since not relevant as long as delegated tasks not run
					 */
					runDelegatedTasks();
					break; // keep on unwrapping (isTryingToUnwrap = true)


					/* (Only active while HANDSHAKING) */
				case NEED_UNWRAP:
				case NEED_UNWRAP_AGAIN:

					switch(unwrapResult.getStatus()) {


					/* 
					 * The SSLEngine was not able to unwrap the incoming data because there 
					 * were not enough source bytes available to make a complete packet. Since
					 * applicationInput
					 */
					case BUFFER_UNDERFLOW:
						/* networkInput seems to be sufficiently filled, so must be under-sized */
						if(isNetworkInputHalfFilled()) {
							doubleNetworkInputCapacity();
						}
						/*
						 * In any case, just need to pull more bytes from network 
						 * (/!\ without flashing current ones)
						 */
						// asynchronous, so stop unwrapping and resume on AIO completion
						return true; // need more data

						/*
						 * SSLEngine was not able to process the operation because there 
						 * are not enough bytes available in the destination buffer 
						 * (ApplicationInput) to hold the result.
						 */
					case BUFFER_OVERFLOW:
						/*
						 * applicationInput is always drained before unwrapping, so BUFFER_OVERFLOW
						 * can only result from an under-sized buffer
						 */
						doubleApplicationInputBufferCapacity();

						break; // retry unwrapping

					case CLOSED:
						close();
						return false; // terminal no need to read more data

					case OK:
						break; // keep on unwrapping with no preliminary step
					}
					//throw new SSLException("Unsupported unwrap result status: "+unwrapResult.getStatus());
					break;


					/*
					 * (Only active while HANDSHAKING)
					 */
				case NEED_WRAP:

					/* trigger outbound wrapping */
					endpoint.getOutbound().requestWrap();
					return false; // no need to read more data


				case FINISHED:

					/* end of handshaking, start independent working of inbound/outbound, so
					 * trigger outbound wrapping just to ensure it is active*/
					endpoint.getOutbound().requestWrap();

					/* could notify end of handshaking here */
					// -> continue on next case

				case NOT_HANDSHAKING:

					switch(unwrapResult.getStatus()) {

					/* 
					 * The SSLEngine was not able to unwrap the incoming data because there 
					 * were not enough source bytes available to make a complete packet. Since
					 * applicationInput
					 */
					case BUFFER_UNDERFLOW:
						/* networkInput seems to be sufficiently filled, so must be under-sized */
						if(isNetworkInputHalfFilled()) {
							doubleNetworkInputCapacity();
						}
						/*
						 * In any case, just need to pull more bytes from network 
						 * (/!\ without flashing current ones)
						 */
						return true;

						/*
						 * SSLEngine was not able to process the operation because there 
						 * are not enough bytes available in the destination buffer 
						 * (ApplicationInput) to hold the result.
						 */
					case BUFFER_OVERFLOW:
						/*
						 * applicationInput is always drained before unwrapping, so BUFFER_OVERFLOW
						 * can only result from an under-sized buffer
						 */
						doubleApplicationInputBufferCapacity();
						break; // retry unwrapping

					case CLOSED:
						close();
						return false; // terminal, no need for more bytes

					case OK:

						/* 
						 * ALWAYS drain to supply the upper layer with app data
						 * as EARLY as possible
						 */
						// <drain>

						// flip buffer to prepare reading (see SSL_EndPoint.onReceived contract).
						/* application input buffer -> WRITE */
						applicationBuffer.flip();

						// apply
						onReceived(applicationBuffer);

						// since endPoint.onReceived read ALL data, nothing left, so clear
						/* application input buffer -> READ */
						applicationBuffer.clear();

						// </drain>
						break; // keep on unwrapping with no preliminary step
					}
					//throw new SSLException("Unsupported unwrap result status: "+unwrapResult.getStatus());
					break;

				}	
			}
			/*
			 * If we exit loop without a specific request for more bytes, 
			 * no additional bytes required
			 */
			return false;
		}
		catch (SSLException e) {
			if(isVerbose) {
				e.printStackTrace();
			}
			close();
			return false;
		}
	};



	public void close() {
		isClosed = true;
	}


	private void runDelegatedTasks() {
		Runnable runnable;
		while ((runnable = engine.getDelegatedTask()) != null) {
			if(isVerbose) {
				System.out.println("\trunning delegated task...");	
			}
			runnable.run();
		}
	};

	private void doubleApplicationInputBufferCapacity() throws SSLException {
		int increasedSize = 2 * applicationBuffer.capacity();
		if (isVerbose) {
			System.out
			.println("[SSL/" + name + "] " + "Application input buffer capacity increased to " + increasedSize);
		}

		if (increasedSize > 4 * engine.getSession().getApplicationBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networkInput capacity is now 4x getApplicationBufferSize. " + "Seen as excessive");
		}

		ByteBuffer extendedBuffer = ByteBuffer.allocate(increasedSize);
		applicationBuffer.flip();
		extendedBuffer.put(applicationBuffer);
		applicationBuffer = extendedBuffer;
	}


	private boolean isNetworkInputHalfFilled() {
		return networkBuffer.position()>networkBuffer.capacity()/2;
	}


	private void doubleNetworkInputCapacity() throws SSLException {

		int increasedSize = 2 * networkBuffer.capacity();
		if (isVerbose) {
			System.out.println("[SSL_NetworkInput] " + name + 
					" -> Network input buffer capacity increased to " 
					+ increasedSize);
		}
		if (increasedSize > 4 * engine.getSession().getPacketBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networkInput capacity is now 4x getPacketBufferSize. " +
					"Seen as excessive");
		}

		ByteBuffer extendedBuffer = ByteBuffer.allocate(increasedSize);
		networkBuffer.flip();
		extendedBuffer.put(networkBuffer);
		networkBuffer = extendedBuffer;
	}


}
