package com.qx.back.io.ssl;

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.ReadPendingException;
import java.nio.channels.ShutdownChannelGroupException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

import com.qx.back.base.reactive.QxIOReactive;


/**
 * <p>
 * SSL_Outbound
 * </p>
 * 
 * @author pc
 *
 */
public class SSL_Outbound {

	private QxIOReactive sender;

	private String name;

	private SSL_Endpoint endpoint;

	private SSLEngine engine;

	/**
	 * Typical required APPLICATION_OUTPUT_STARTING_CAPACITY is 16704. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408.
	 * Replace by 2^15 (for beauty purposes)
	 */
	public final static int APPLICATION_OUTPUT_STARTING_CAPACITY = 32768;

	private ByteBuffer applicationBuffer;


	private AsynchronousSocketChannel channel;

	private long timeout;

	private ExecutorService internalExecutor;

	private boolean isVerbose;

	private boolean isClosed;

	/**
	 * flag = (is currently sending)
	 * Boolean set/read operations are guaranteed atomic, thus thread-safe
	 */
	private AtomicBoolean isWritePending;


	/**
	 * Typical required NETWORK_OUTPUT_STARTING_CAPACITY is 16709. Instead, we add 
	 * security margin up to: 2^14+2^10 = 17408
	 */
	public final static int NETWORK_OUTPUT_STARTING_CAPACITY = 32768;


	protected ByteBuffer networkBuffer;

	private boolean isWrapRequested;


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
		isWrapRequested = false;

		// set parameters


		networkBuffer = ByteBuffer.allocate(NETWORK_OUTPUT_STARTING_CAPACITY);		
		networkBuffer.position(0);
		networkBuffer.limit(0);

		// initial setup
		isWritePending = new AtomicBoolean(false);

		isClosed = false;
	}



	/**
	 * If a reception/sending in progress, will queue the task.
	 * If no operation currently running, will start immediately 
	 * the task
	 * @param state the task to be started
	 */
	public void requestWrap() {
		if(!isClosed) {
			/* not yet running, start immediately */
			if(isWritePending.compareAndSet(false, true)) {
				isWritePending.set(true);
				wrap();
			}
			/* already running, notify */
			else {
				isWrapRequested = true;
			}		
		}
	}





	private void wrap() {

		/* Not everything has been written, so compact (switch to write mode) */
		networkBuffer.compact();

		/* wrap as much as possible to buffer */
		boolean thenWrapAgain = unsafeWrap();

		/* (switch back to read mode) for AIO.write */
		networkBuffer.flip();

		// if there is actually new bytes, send them
		if(networkBuffer.hasRemaining()) {
			try {
				channel.write(networkBuffer, timeout, TimeUnit.SECONDS, null, 
						new CompletionHandler<Integer, Void>() {

					@Override
					public void completed(Integer nBytes, Void attachment) {

						if(nBytes==-1) {
							close();
							throw new RuntimeException("[Debug] unexpected close");
						}
						else if(thenWrapAgain && !isClosed){
							// then try to wrap again
							internalExecutor.submit(new Runnable() {
								public @Override void run() {
									wrap();
								}
							});
						}
						else {
							isWritePending.set(false);
						}
					}

					@Override
					public void failed(Throwable exc, Void attachment) {
						if(isVerbose) {
							exc.printStackTrace();
						}
						close();
					}
				});
			}
			catch (IllegalArgumentException | ReadPendingException |
					NotYetConnectedException | ShutdownChannelGroupException e) {
				if(isVerbose) {
					e.printStackTrace();
				}
				close();
			}
		}
		/* do not need more bytes, but need another wrap 
		 * (that may in turn request more bytes)
		 */
		else if(isWrapRequested) {
			isWrapRequested = false;
			wrap();
		}
		else {
			/* nothing more to write, go back to idle state, 
			 * waiting to be later resumed */
			isWritePending.set(false);
		}
	}



	/**
	 * 
	 * @return a flag indicating:
	 *         <ul>
	 *         <li>false: means <b>WAIT</b>, Used in SSLHandshaking phase, when we
	 *         must fall into passive mode to let sslEngine perform unwrap and then
	 *         call back wrap().</li>
	 *         <li>true: means <b>WRITE_THEN_WRAP_AGAIN</b>. Used when
	 *         SSLHandshaking phase is completed.</li>
	 *         </ul>
	 */
	private boolean unsafeWrap() {

		/* <retrieve> */
		/*
		 * application output buffer -> WRITE
		 * NB: Application output buffer is left in read mode all the time,
		 * except in this state scope.
		 */
		applicationBuffer.compact();

		sender.onReceived(applicationBuffer);

		/* application output buffer -> READ */
		applicationBuffer.flip();

		/* </retrieve> */

		try {
			while(!isClosed) {

				if(isVerbose) {
					System.out.println("\t--->"+name+" is wrapping... ");
				}

				/* wrapping */
				SSLEngineResult wrapResult = engine.wrap(applicationBuffer, networkBuffer);

				if(isVerbose) {
					System.out.println(name+": "+wrapResult);
				}

				// end point listening to result for updating phase
				endpoint.onResult(wrapResult);

				/* <handshake-status> */
				switch(wrapResult.getHandshakeStatus()) {

				case NEED_TASK:
					/* run delegated tasks and then see what's required next */
					runDelegatedTasks();
					break; // keep on wrapping

				case NEED_WRAP: 
					switch(wrapResult.getStatus()) {

					case BUFFER_UNDERFLOW: // not supposed to happen
						throw new SSLException("Strange error: BUFFER_UNDERFLOW while wrapping");

						/* 
						 * Handle the <code>wrap(applicationOutput, networkOutput)</code> 
						 * case when the SSLEngine was not able to process the operation 
						 * because there are not enough bytes available in the destination 
						 * buffer to hold the result.
						 */
					case BUFFER_OVERFLOW: 

						/* Network output is not even half-filled, so assume that it is 
						 * under-sized 
						 */
						if(!isNetworkBufferHalfFilled()) {
							doubleNetworkBufferCapacity();
							/* retry wrapping, just break */
						}

						else {
							/*
							 * Network output is almost filled, so best solution is to send. But since we
							 * are in handshaking phase, must return to unsafeWrap once networkBuffer bytes have
							 * been written out
							 */
							return true;
						}
						break; // retry to wrap

					case CLOSED: 
						close();
						/*
						 * Just flush bytes, but do not require re-launching 
						 * unsafeWrap after that
						 */
						return false;


					case OK:
						/*
						 * Since we already are in wrap mode, try concatenating the next wrap into the
						 * networkBuffer, so try to wrap again
						 */
						break;

					}
					/* </status> */
					break;

				case NEED_UNWRAP:
				case NEED_UNWRAP_AGAIN: 

					/*
					 * Trigger the other side
					 */
					endpoint.unwrap();

					/*
					 * We are in handshaking phase, so just flush what's have already been wrapped
					 * into the networkBuffer, but do not require immediate call back to unsafeWrap.
					 * Instead, wait for the SSL_Inbound side to call back for this side.
					 */
					return false; 	


				case FINISHED: 

					switch(wrapResult.getStatus()) {

					case CLOSED: 
						return false;

					case BUFFER_OVERFLOW:
					case BUFFER_UNDERFLOW:
						return true; // not supposed to happen

					case OK:

						/*
						 * End of handshaking, start independent working of inbound/outbound. Since
						 * Inbound MIGHT have been left in idle mode, wake it up to ensure it is active
						 */
						endpoint.unwrap();
						// -> continue to next case
						break;
					}



				case NOT_HANDSHAKING: // application data


					switch(wrapResult.getStatus()) {

					case CLOSED: 
						close();
						/*
						 * Just flush bytes, but do not require re-launching 
						 * unsafeWrap after that
						 */
						return false;

					case BUFFER_UNDERFLOW: // not supposed to happen
						throw new RuntimeException("Unexpected situation");



						/* 
						 * Handle the <code>wrap(applicationOutput, networkOutput)</code> 
						 * case when the SSLEngine was not able to process the operation 
						 * because there are not enough bytes available in the destination 
						 * buffer to hold the result.
						 */
					case BUFFER_OVERFLOW: 

						/* Network output is not even half-filled, so assume that it is 
						 * under-sized 
						 */
						if(!isNetworkBufferHalfFilled()) {
							doubleNetworkBufferCapacity();
							// buffer expansion -> retry to wrap
						}
						else {
							/*
							 * Network output is almost filled, so best solution is to send.
							 * BUT, we are not done, so ask for calling back unsafeWrap.
							 */
							return true;
						}
						break; 	


					case OK:

						switch(wrapResult.getStatus()) {

						case CLOSED: 
							close();
							/*
							 * Just flush bytes, but do not require re-launching 
							 * unsafeWrap after that
							 */
							return false;

						case BUFFER_OVERFLOW:
						case BUFFER_UNDERFLOW:
						case OK:
							break;
						default:
							break;
						}

						/*
						 * no more wrapping is requested, so end up here. But we are now in stream mode
						 * (handshake is now completed), so ALWAYS ask for more wrapping. 
						 * 
						 * NOTE: if applicationBuffer is depleted, then networkBuffer will remain empty and
						 * wrap() method will stop by itself.
						 */
						return true;

					}
					/* </status> */
					break;

				}
				/* </handshake-status> */
			}
			return false;
		}
		catch (SSLException e) {
			if(isVerbose) {
				e.printStackTrace();
			}
			close();

			// Everything went wrong, so stop wrapping...
			return false;
		}
	};




	/**
	 * The operation just closed this side of the SSLEngine, or the 
	 * operation could not be completed because it was already closed.
	 */
	public void close() {

		// Signals that no more outbound application data will be sent on this SSLEngine.
		//engine.closeOutbound();

		/*
		System.out.println("SSL_Outbound: closing outbound");

		if(endpoint.isVerbose()) {

		}
		 */
		//isClosed = true;

	}





	/**
	 * delegated-tasks
	 */
	private void runDelegatedTasks() {
		Runnable runnable;
		while ((runnable = engine.getDelegatedTask()) != null) {
			if(isVerbose) {
				System.out.println("\trunning delegated task...");	
			}
			runnable.run();
		}
	}





	private boolean isNetworkBufferHalfFilled() {
		return networkBuffer.position()>networkBuffer.capacity()/2;
	}


	/**
	 * Double buffer capacity
	 * 
	 * @param engine
	 * @throws SSLException
	 */
	private void doubleNetworkBufferCapacity() throws SSLException {

		int increasedSize = 2 * networkBuffer.capacity();
		if (isVerbose) {
			System.out.println("[SSL] " +name+ " : Network output buffer capacity increased to " + increasedSize);
		}
		if (increasedSize > 4 * engine.getSession().getPacketBufferSize()) {
			throw new SSLException(
					"[SSL_Inbound] networ output capacity is now 4x getPacketBufferSize. " + "Seen as excessive");
		}

		ByteBuffer extendedBuffer = ByteBuffer.allocate(increasedSize);
		networkBuffer.flip();
		extendedBuffer.put(networkBuffer);
		networkBuffer = extendedBuffer;
	}


}
