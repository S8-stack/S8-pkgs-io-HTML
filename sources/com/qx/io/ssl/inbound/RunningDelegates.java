package com.qx.io.ssl.inbound;

public class RunningDelegates extends SSL_Inbound.Mode {

	private SSL_Inbound.Mode callback;
	
	public RunningDelegates(SSL_Inbound inbound, SSL_Inbound.Mode callback) {
		inbound.super();
		
		this.callback = callback;
	}


	@Override
	public String declare() {
		return "is running delegated task...";
	}

	
	@Override
	public void run(SSL_Inbound.Process process) {

		Runnable taskRunnable = getEngine().getDelegatedTask();

		if(taskRunnable!=null) {
			
			// perform the task
			taskRunnable.run();

			process.mode = callback;
			process.isRunning = true;
		}	
	}

}
