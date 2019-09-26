/**
 * 
 */
package com.tcs.demo.recipe.service;

import java.beans.FeatureDescriptor;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.tcs.demo.recipe.bean.Recipe;
import com.tcs.demo.recipe.repository.RecipeRespository;



/**
 * @author Dhiraj
 *
 */
@Service
public class RecipeServiceImpl implements RecipeService {

	@Autowired
	RecipeRespository recipeRepository;
	
	@Override
	public Recipe addRecipe(Recipe recipe) {
		recipe.setRcpCreatedAt(null);
		recipe.setRcpUpdatedAt(null);
		recipe.setRcpUpdatedBy(null);
		recipe.setRcpRowState(1);
		return recipeRepository.saveAndFlush(recipe);
	}

	@Override
	public Recipe deleteRecipe(Long rcpId, Long editor) {
		Recipe existingRecipe = recipeRepository.findByRcpIdAndRcpRowState(rcpId, 1);
		existingRecipe.setRcpRowState(-1);
		existingRecipe.setRcpUpdatedBy(editor);
		 return recipeRepository.saveAndFlush(existingRecipe);		
	}

	
	@Override
	public Recipe updateRecipe(Recipe recipe) {
		Recipe existingRecipe = recipeRepository.findByRcpIdAndRcpRowState(recipe.getRcpId(), 1);
		String[] ignoredProperties = getNullPropertyNames(recipe);
		BeanUtils.copyProperties(recipe, existingRecipe,ignoredProperties);
		return recipeRepository.save(existingRecipe);
	}


	@Override
	public Recipe getRecipe(Long rcpId) {
		return recipeRepository.findByRcpIdAndRcpRowState(rcpId, 1);
	}


	@Override
	public List<Recipe> getAllRecipes() {
		return recipeRepository.findAllByRcpRowState(1);
	}

	/* (non-Javadoc)
	 * @see com.tcs.recipe_jpa.service.RecipeService#getRecipes(int, int)
	 */
	@Override
	public Page<Recipe> getRecipes(int pageNumber,int limit) {
		Pageable pageable = PageRequest.of(pageNumber, limit);
		return recipeRepository.findAllByRcpRowState(1, pageable);
	}

	
	private String[] getNullPropertyNames(Recipe recipe) {
		BeanWrapper wrapped = new BeanWrapperImpl(recipe);
		
		return Stream.of(wrapped.getPropertyDescriptors())
	            .map(FeatureDescriptor::getName)
	            .filter(propertyName -> wrapped.getPropertyValue(propertyName) == null)
	            .toArray(String[]::new);
		
	}


}
