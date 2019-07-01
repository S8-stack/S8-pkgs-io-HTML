package com.qx.back.io.ssl.outbound;

import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;

public class RunningDelegates extends SSL_OutboundMode {

	private boolean isVerbose;

	private SSLEngine engine;

	public ExecutorService internalExecutor;

	private SSL_Outbound outbound;

	public RunningDelegates() {
		super();
	}

	@Override
	public void bind(SSL_Outbound outbound) {
		this.outbound = outbound;
		isVerbose = outbound.isVerbose;
		engine = outbound.engine;
		internalExecutor = outbound.internalExecutor;
	}

	public class Task extends SSL_OutboundMode.Task {
		
		public SSL_OutboundMode.Task callback;
		
		public Task(SSL_OutboundMode.Task callback) {
			super();
			this.callback = callback;
		}
		
		@Override
		public SSL_OutboundMode.Task run() {

			Runnable taskRunnable = engine.getDelegatedTask();

			if(taskRunnable!=null) {
				if(isVerbose) {
					System.out.println("\trunning delegated task...");	
				}
				internalExecutor.execute(new Runnable() {

					@Override
					public void run() {

						// perform the task
						taskRunnable.run();

						// then try to run other task
						outbound.run(RunningDelegates.Task.this);
					}
				});
				return null; // stop here and wait for the task to awake back inbound
			}
			else {
				/*
				 * Directly switch back to callback
				 */
				return callback;
			}
		}
	}
}
