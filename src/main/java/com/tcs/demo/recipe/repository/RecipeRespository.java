/**
 * 
 */
package com.tcs.demo.recipe.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tcs.demo.recipe.bean.Recipe;



/**
 * Repository extending JpaRepository with additional Spring Data JPA Derived Queries methods
 * @author Dhiraj
 *
 */
@Repository
public interface RecipeRespository extends JpaRepository<Recipe,Long>{
	/**
	 * Find recipe with (where rcpid=? and rcprowstate=?)
	 * @param rcpId
	 * @param rcpRowState
	 * @return Recpie
	 */
	Recipe findByRcpIdAndRcpRowState(Long rcpId,Integer rcpRowState);
	
	/**
	 * Find all recipes with (where rcprowstate=?)
	 * @param rcpRowState
	 * @return List
	 */
	List<Recipe> findAllByRcpRowState(Integer rcpRowState);
	
	/**
	 * Returns a Page of entities meeting the paging restriction provided in the Pageable object and (where rcprowstate=?).
	 * @param rcpRowState
	 * @param pageable
	 * @return
	 */
	Page<Recipe> findAllByRcpRowState(Integer rcpRowState,Pageable pageable);
	
	/**
	 * Find recipe with (rcpname=? and rcprowstate=?)
	 * @param rcpName
	 * @param rcpRowState
	 * @return
	 */
	Recipe findByRcpNameAndRcpRowState(String rcpName,Integer rcpRowState);

}
