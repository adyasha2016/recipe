/**
 * 
 */
package com.tcs.demo.recipe.config;

import java.security.GeneralSecurityException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.tcs.demo.recipe.service.SecurityUserDetailService;
import com.tcs.demo.recipe.util.EncryptionUtil;

/**
 * Manage spring security configuration to web and api access
 * @author Dhiraj
 *
 */
@EnableWebSecurity
public class MultiHttpSecurityConfig {

	@Autowired
	SecurityUserDetailService securityUserDetailService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new PasswordEncoder() {
			@Override
			public String encode(CharSequence rawPassword) {
				try {
					return EncryptionUtil.encrypt(rawPassword.toString());
				} catch (GeneralSecurityException e) {
					return null;
				}
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				try {
					return rawPassword.toString().equals(EncryptionUtil.decrypt(encodedPassword));
				} catch (GeneralSecurityException e) {
					return false;
				}
			}
		};
	}

	@Bean
	public DaoAuthenticationProvider authProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(securityUserDetailService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	/**
	 * Manage spring security config to api calls
	 * @author Dhiraj
	 *
	 */
	@Configuration
	@Order(1)
	public  class ApiSecurityConfig extends WebSecurityConfigurerAdapter{

		@Autowired
		ApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

		private static final String API_URL = "/api/**";
		private static final String ADMIN = "ADMIN";

		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(authProvider());
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception{

			http.antMatcher(API_URL)                             
			.authorizeRequests()
			.antMatchers(HttpMethod.GET, API_URL).hasAnyRole("USER",ADMIN)
			.antMatchers(HttpMethod.POST, API_URL).hasRole(ADMIN)
			.antMatchers(HttpMethod.PUT, API_URL).hasRole(ADMIN)
			.antMatchers(HttpMethod.DELETE, API_URL).hasRole(ADMIN)
			.and()
			.httpBasic()
			.realmName("TCS_RECIPE") // exception caused if not specified : Error creating bean with name 'apiAuthenticationEntryPoint': java.lang.IllegalArgumentException: realmName must be specified 
			.and().exceptionHandling() .authenticationEntryPoint(apiAuthenticationEntryPoint).and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.csrf().disable()
			.formLogin().disable();
		}
	}

	/**
	 * Manage spring security config for web calls
	 * @author Dhiraj
	 *
	 */
	@Configuration
	public  class  WebSecurityConfig extends WebSecurityConfigurerAdapter{

		private static final String LOGIN_URL = "/login";


		@Value("${spring.h2.console.path}")
		String h2ConsolePath;

		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(authProvider());
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception{
			http.csrf().disable();
			http.authorizeRequests().antMatchers(LOGIN_URL).permitAll();
			http.authorizeRequests().antMatchers(h2ConsolePath+"/**").permitAll().and().headers().frameOptions().disable();
			http.authorizeRequests().antMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources", "/configuration/security", 
					"/swagger-ui.html", "/webjars/**", "/swagger-resources/configuration/ui", "/swagge‌​r-ui.html", "/swagger-resources/configuration/security").permitAll();

			http.authorizeRequests().anyRequest().authenticated().and().formLogin()
			.loginPage(LOGIN_URL)
			.loginProcessingUrl("/perform_login")
			.defaultSuccessUrl("/home")
			.failureUrl("/login?error=true")
			.usernameParameter("username")
			.passwordParameter("password")
			.and().logout().logoutUrl("/logout").logoutSuccessUrl(LOGIN_URL);

		}
	}
}
