package com.tcs.demo.recipe.controller;


import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.validation.Valid;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.tcs.demo.recipe.bean.User;
import com.tcs.demo.recipe.service.UserService;





/**
 * Controller to handle HTTP Operations for User 
 * @author Dhiraj
 *
 */

@RestController
@RequestMapping("api/users")
public class UserController {

	private final static Logger LOGGER = LogManager.getLogger(UserController.class);

	@Autowired
	UserService userService;

	/**
	 * Fetch the user based on id.
	 * @path http://localhost:8080/recipe/users/{id}
	 * @param id
	 * @return json representation of User Object
	 */
	@GetMapping(value = "{id}", produces=MediaType.APPLICATION_JSON_VALUE) 
	public ResponseEntity<User>   getUserById(@PathVariable("id") Long id) {
		User user =  userService.getUserById(id);
		if(user == null) {
			throw new UserNotFoundException("User not found with id  "+id);
		}else {
			return  new ResponseEntity<>(user, HttpStatus.OK);
		}
	}

	/**
	 * Fetch the user based on loginid.
	 * @mapsTo http://localhost:8080/recipe/users?loginid={loginid}
	 * @param userLoginId
	 * @return json representation of User Object
	 */
	@GetMapping(produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<User>  getUserByLoginId(@RequestParam("loginid") String userLoginId) {
		User user =  userService.getUserByLoginId(userLoginId);
		
		if(user == null) {
			throw new UserNotFoundException("User not found with loginid "+userLoginId);
		}else {
			return  new ResponseEntity<>(user, HttpStatus.OK);
		}
	}

	/**
	 * Add the user to database
	 * @param user
	 * @return json representation of User Object
	 * @throws GeneralSecurityException 
	 * @throws UnsupportedEncodingException 
	 */
	@PostMapping(consumes=MediaType.APPLICATION_JSON_VALUE,  produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<User> addUser(@Valid @RequestBody User user) throws UnsupportedEncodingException, GeneralSecurityException {
		user = userService.addNewUser(user);
		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
		.buildAndExpand(user.getUsrId()).toUri();
		
		LOGGER.info("Created User "+user.toString()+" with location "+uri.toString());
		
		return  ResponseEntity.created(uri).body(user); //set the Location header to newly created resource with 201 created status
	
	}
	
	/**
	 * Exception thrown when id passed is invalid / user table is empty
	 * @author Dhiraj
	 *
	 */
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public class UserNotFoundException extends RuntimeException{

		private static final long serialVersionUID = 1L;
		
		public UserNotFoundException(String exception) {
			super(exception);
		}
		
	}


}