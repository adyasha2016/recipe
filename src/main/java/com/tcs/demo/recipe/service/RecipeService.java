/**
 * 
 */
package com.tcs.demo.recipe.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.tcs.demo.recipe.bean.Recipe;



/**
 * @author Dhiraj
 *
 */
public interface RecipeService {

	/**
	 * Add a new Recipe
	 * @param recipe
	 * @return new Recipe with generated id
	 */
	Recipe addRecipe(Recipe recipe);
	
	/**
	 * Delete a recipe using id
	 * @param id
	 */
	Recipe deleteRecipe(Long rcpId,Long editor);
	
	/**
	 * Update an exising recipe
	 * @param recipe
	 * @return updated recipe
	 */
	Recipe  updateRecipe(Recipe recipe);
	
	/**
	 * Get arecipe by id
	 * @param id
	 * @return
	 */
	Recipe getRecipe(Long rcpId);
	
	/**
	 * Get all recipes
	 * @return List<Recipe>
	 */
	List<Recipe> getAllRecipes();
		
	/**
	 * Returns the Page object containing the list of recipe with passed limit and page number
	 * @param pageNumber
	 * @param limit
	 * @return Page
	 */
	Page<Recipe> getRecipes(int pageNumber,int limit);
}
