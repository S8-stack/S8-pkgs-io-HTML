package com.qx.io.html;


import java.io.IOException;
import java.io.Writer;


/**
 * 
 * @author pierreconvert
 *
 */
public class HTML_Header1 extends HTML_Block {

	private String title;
	
	
	public HTML_Header1(String title) {
		this.title = title;
	}


	@Override
	public void print(Writer writer) throws IOException {
		writer.write("<h1>");
		writer.write(title);
		writer.write("</h1>");
	}

}