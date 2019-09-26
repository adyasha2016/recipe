/**
 * 
 */
package com.tcs.demo.recipe.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tcs.demo.recipe.bean.User;



/**
 * Repository extending  JpaRepository along with additional Spring Data JPA Derived Queries methods
 * @author Dhiraj
 *
 */
@Repository
public interface UserRepository extends JpaRepository<User,Long>{
	
	/**
	 * Find user by (where usrloginid=? and usrrowstate=?)
	 * @param usrLoginId
	 * @return
	 */
	User findByUsrLoginIdAndUsrRowState(String usrLoginId,Integer usrRowState);
	
	
	/**
	 * Find user by (where usrid=? and usrrowstate=?)
	 * @param usrLoginId
	 * @return
	 */
	User findByUsrIdAndUsrRowState(Long usrId,Integer usrRowState);

}
