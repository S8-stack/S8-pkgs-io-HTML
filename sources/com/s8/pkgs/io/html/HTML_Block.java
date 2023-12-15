package com.s8.pkgs.io.html;

import java.io.IOException;
import java.io.Writer;


/**
 * 
 * @author Pierre Convert
 *
 */
public abstract class HTML_Block {
	
	
  public HTML_Block() {
	  super();
  }
  
  public abstract void print(Writer writer) throws IOException;
  
}