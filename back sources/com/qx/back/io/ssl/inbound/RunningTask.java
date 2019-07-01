package com.qx.back.io.ssl.inbound;

import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLEngine;

public class RunningTask extends SSL_InboundMode {

	
	private SSLEngine engine;

	public ExecutorService internalExecutor;
	
	private Unwrapping unwrapping;

	private boolean isVerbose;
	
	private SSL_Inbound inbound;
	
	public RunningTask() {
		super();
	}

	@Override
	public void bind(SSL_Inbound inbound) {

		this.inbound = inbound;
		
		engine = inbound.engine;
		internalExecutor = inbound.internalExecutor;
		unwrapping = inbound.unwrapping;
		
		isVerbose = inbound.isVerbose;
	}
	
	
	public class Task extends SSL_InboundMode.Task {
		
		@Override
		public SSL_InboundMode.Task run() {
			
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
						inbound.run(RunningTask.Task.this);
					}
				});
				return null; // stop here and wait for the task to awake back inbound
			}
			else {
				/*
				 * Directly switch back to unwrapping
				 */
				return unwrapping.new Task();
			}
		}	
	}

	

}
