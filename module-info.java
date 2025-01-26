
/**
 * 
 * @author pierreconvert
 *
 */
module com.s8.pkgs.io.svg {
	
	exports com.s8.pkgs.io.svg;
	exports com.s8.pkgs.io.svg.elements;
	exports com.s8.pkgs.io.svg.elements.shapes;
	exports com.s8.pkgs.io.svg.elements.shapes.path;
	exports com.s8.pkgs.io.svg.elements.shapes.primitives;
	
	exports com.s8.pkgs.io.svg.transform;
	exports com.s8.pkgs.io.svg.maths;
	
	exports com.s8.pkgs.io.svg.styles;
	
	

	exports com.s8.pkgs.io.svg.web;
	exports com.s8.pkgs.io.svg.web.shapes;
	
	requires transitive com.s8.api;
	requires transitive com.s8.build;
	requires transitive com.s8.pkgs.ui.carbide;
	

}