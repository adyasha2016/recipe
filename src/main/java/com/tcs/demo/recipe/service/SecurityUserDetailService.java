package com.tcs.demo.recipe.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tcs.demo.recipe.bean.User;



@Service
public class SecurityUserDetailService implements UserDetailsService{

	@Autowired
	UserService  userService;
	
	@Override
	public UserDetails loadUserByUsername(String userLoginId) {
		User user = userService.getUserByLoginId(userLoginId);
		if (user == null) {
			throw new UsernameNotFoundException("User " + userLoginId + " was not found in the database");
		}
		
		 List<GrantedAuthority> grantList = new ArrayList<>();
		 if(user.getUsrIsAdmin()) {
			 GrantedAuthority adminAuthority= new SimpleGrantedAuthority("ROLE_ADMIN");
			 GrantedAuthority userAuthority= new SimpleGrantedAuthority("ROLE_USER");
			 grantList.add(adminAuthority);
			 grantList.add(userAuthority);
		 }else {
			 GrantedAuthority userAuthority= new SimpleGrantedAuthority("ROLE_USER");
			 grantList.add(userAuthority);
		 }
		 
		 
		   return new org.springframework.security.core.userdetails.User(user.getUsrLoginId(), 
				   user.getUsrPassword()	, grantList);
	 
	     
	}

}
