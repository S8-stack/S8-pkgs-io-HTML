package com.qx.io.html;

import java.io.IOException;
import java.io.Writer;

public abstract class HTML_Block {
	
	
  public HTML_Block() {
	  super();
  }
  
  public abstract void print(Writer writer) throws IOException;
  
}