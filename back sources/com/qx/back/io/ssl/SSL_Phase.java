package com.qx.back.io.ssl;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.Status;

/**
 * Javadoc on <code>SSLEngine</code>: There are five distinct phases to an SSLEngine.
 * @author pc
 *
 */
public enum SSL_Phase {

	/**
	 * The SSLEngine has been created and initialized, but has not yet been used.
	 * During this phase, an application may set any SSLEngine-specific settings
	 * (enabled cipher suites, whether the SSLEngine should handshake in client or
	 * server mode, and so on). Once handshaking has begun, though, any new settings
	 * (except client/server mode, see below) will be used for the next handshake.
	 */
	CREATION {
		public @Override SSL_Phase transition(SSLEngineResult result) {
			if(result.bytesConsumed()>0 || result.bytesProduced()>0) {
				return INITIAL_HANDSHAKE;
			}
			else {
				return CREATION;
			}
		}
	},

	/**
	 * Initial Handshake - The initial handshake is a procedure by which the two
	 * peers exchange communication parameters until an SSLSession is established.
	 * Application data can not be sent during this phase.
	 * 
	 */
	INITIAL_HANDSHAKE {
		public @Override SSL_Phase transition(SSLEngineResult result) {
			if(result.getStatus()==Status.CLOSED) {
				return CLOSURE;
			}
			switch (result.getHandshakeStatus()) {
			case NOT_HANDSHAKING:
			case FINISHED: 
				return APPLICATION_DATA;

			case NEED_TASK: 
			case NEED_UNWRAP:
			case NEED_UNWRAP_AGAIN:
			case NEED_WRAP: 
			default: 
				return INITIAL_HANDSHAKE;
			}
		}
	},

	/**
	 * Application Data - Once the communication parameters have been established
	 * and the handshake is complete, application data may flow through the
	 * SSLEngine. Outbound application messages are encrypted and integrity
	 * protected, and inbound messages reverse the process.
	 * 
	 */
	APPLICATION_DATA {
		public @Override SSL_Phase transition(SSLEngineResult result) {
			if(result.getStatus()==Status.CLOSED) {
				return CLOSURE;
			}
			switch (result.getHandshakeStatus()) {
			case NOT_HANDSHAKING:
			case FINISHED: 
				return APPLICATION_DATA;

			case NEED_TASK: 
			case NEED_UNWRAP:
			case NEED_UNWRAP_AGAIN:
			case NEED_WRAP: 
			default: 
				return REHANDSHAKING;
			}
		}
	},

	/**
	 * Rehandshaking - Either side may request a renegotiation of the session at any
	 * time during the Application Data phase. New handshaking data can be
	 * intermixed among the application data. Before starting the rehandshake phase,
	 * the application may reset the SSL/TLS communication parameters such as the
	 * list of enabled ciphersuites and whether to use client authentication, but
	 * can not change between client/server modes. As before, once handshaking has
	 * begun, any new SSLEngine configuration settings will not be used until the
	 * next handshake.
	 * 
	 */
	REHANDSHAKING {
		public @Override SSL_Phase transition(SSLEngineResult result) {
			if(result.getStatus()==Status.CLOSED) {
				return CLOSURE;
			}
			switch (result.getHandshakeStatus()) {
			case NOT_HANDSHAKING:
			case FINISHED: 
				return APPLICATION_DATA;

			case NEED_TASK: 
			case NEED_UNWRAP:
			case NEED_UNWRAP_AGAIN:
			case NEED_WRAP: 
			default: 
				return INITIAL_HANDSHAKE;
			}
		}
	},

	/**
	 * Closure - When the connection is no longer needed, the application should
	 * close the SSLEngine and should send/receive any remaining messages to the
	 * peer before closing the underlying transport mechanism. Once an engine is
	 * closed, it is not reusable: a new SSLEngine must be created.
	 */
	CLOSURE {
		public @Override SSL_Phase transition(SSLEngineResult result) {
			return CLOSURE;
		}
	};



	public abstract SSL_Phase transition(SSLEngineResult result);
	

}