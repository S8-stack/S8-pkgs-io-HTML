package com.s8.pkgs.io.html;


import java.io.IOException;
import java.io.Writer;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;



/**
 * 
 * @author pierreconvert
 *
 */
public class HTML_Table01 extends HTML_Block {

	private String name;
	
	private String[] header;
	
	private List<String[]> body;
	
	public static final DecimalFormat STANDARD = new DecimalFormat("0.00");
	
	public static final DecimalFormat SCIENTIFIC = new DecimalFormat("0.00E0");

	
	public HTML_Table01(String name) {
		this.name = name;
		header = new String[] { "Name", "Symbol", "Value", "Unit" };
		body = new ArrayList<>();
	}

	public void setHeader(int columnIndex, String value) {
		header[columnIndex] = value;
	}

	public void pushRow(String... row) {
		body.add(row);
	}

	/**
	 * 
	 * @param name
	 * @param symbol
	 * @param value
	 * @param unit
	 */
	public void append(String name, String symbol, double value, DecimalFormat format, String unitAbbreviation) {
		body.add(new String[] { name, symbol, format.format(value), unitAbbreviation});
	}

	public void append(String name, String value) {
		body.add(new String[] { name, "-", value, "-" });
	}


	@Override
	public void print(Writer writer) throws IOException {
		writer.write("<table class=\"table01\">");

		writer.write("<thead>");
		writer.write("<tr><td colspan=\"4\">" + name + "</td></tr>");
		writer.write("</tr>");
		for (String cell : header) {
			writer.write("<td>");
			writer.write(cell);
			writer.write("</td>");
		}
		writer.write("</tr>");
		writer.write("</thead>");


		writer.write("<tbody>");
		for (String[] row : body) {
			writer.write("<tr>");
			for (String cell : row) {
				writer.write("<td>");
				writer.write(cell);
				writer.write("</td>");
			}
			writer.write("</tr>");
		}
		writer.write("</tbody>");
		writer.write("</table>");
	}

}