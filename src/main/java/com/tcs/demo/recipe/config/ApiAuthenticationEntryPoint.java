/**
 * 
 */
package com.tcs.demo.recipe.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tcs.demo.recipe.bean.ApiError;

/**
 * Entry point for Basic Auth used to access api/** resources
 * @author Dhiraj
 *
 */
@Component
public class ApiAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

	@Override
	public void commence(final HttpServletRequest request, 
			final HttpServletResponse response, 
			final AuthenticationException authException) throws IOException, ServletException {
		//Authentication failed, send error response.
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); 
		response.addHeader("WWW-Authenticate", "Basic realm=" + getRealmName() + "");
		List<String>list = new ArrayList<>();
		list.add(authException.getLocalizedMessage());
		ApiError error = new ApiError(HttpStatus.UNAUTHORIZED, "Basic Authentication required to access protected resource", list);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(new ObjectMapper().writeValueAsString(error));
		
	}

	@Override
	public void afterPropertiesSet()  throws Exception{
		setRealmName("TCS_RECIPE"); //caused Error creating bean with name 'apiAuthenticationEntryPoint'  in MultiHttpSecurityConfig :  java.lang.IllegalArgumentException: realmName must be specified 
		super.afterPropertiesSet(); //Assert.hasText(realmName, "realmName must be specified"); in BasicAuthenticationEntryPoint
	}
}
