package com.tcs.demo.recipe.config;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
/**
 * Configure view controller for html
 * @author Dhiraj
 *
 */
@Component
public class WebMvcConfig implements WebMvcConfigurer{
	
	 @Override
	    public void addViewControllers(ViewControllerRegistry registry)
	    {
	        registry.addViewController("/").setViewName("home.html");
	        registry.addViewController("/home").setViewName("home.html");
	        registry.addViewController("/login").setViewName("login.html");
	    }
}