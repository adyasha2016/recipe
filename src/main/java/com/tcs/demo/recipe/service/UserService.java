package com.tcs.demo.recipe.service;

import com.tcs.demo.recipe.bean.User;

/**
 * Utility methods for User
 * @author Dhiraj
 *
 */
public interface UserService {
	/**
	 * Add a new user to the database
	 * @param user
	 */
	User addNewUser(User user);
	
	/**
	 * Get the user details by loginid
	 * @param userLoginId
	 * @return User
	 */
	User getUserByLoginId(String userLoginId);
	
	/**
	 * Get the user details by id
	 * @param id
	 * @return User
	 */
	User getUserById(Long usrId);
}
