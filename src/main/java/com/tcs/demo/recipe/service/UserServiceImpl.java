package com.tcs.demo.recipe.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tcs.demo.recipe.bean.User;
import com.tcs.demo.recipe.repository.UserRepository;



@Service
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	PasswordEncoder passwordEncoder;

	@Override
	public User addNewUser(User user) {
		user.setUsrPassword(passwordEncoder.encode(user.getUsrPassword()));
		return userRepository.save(user);
	}


	@Override
	public User getUserByLoginId(String userLoginId) {
		
		return userRepository.findByUsrLoginIdAndUsrRowState(userLoginId, 1);
	}


	@Override
	public User getUserById(Long usrId) {
		
		return userRepository.findByUsrIdAndUsrRowState(usrId,1);
	}



}
