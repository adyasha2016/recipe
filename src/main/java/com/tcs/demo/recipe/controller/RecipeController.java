/**
 * 
 */
package com.tcs.demo.recipe.controller;

import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.tcs.demo.recipe.bean.ApiError;
import com.tcs.demo.recipe.bean.Recipe;
import com.tcs.demo.recipe.service.RecipeService;
import com.tcs.demo.recipe.service.UserService;
import com.tcs.demo.recipe.util.FileUploadUtil;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * Controller to handle HTTP Operations for Recipe 
 * @author Dhiraj
 *
 */

@RestController
@RequestMapping("api/recipes")
@Api(value="Recipe  Controller")
public class RecipeController {


	private static final  Logger LOGGER = LogManager.getLogger(RecipeController.class);

	@Autowired
	RecipeService recipeService;

	@Autowired
	UserService userService;

	/**
	 * Get all recipes based on the limit and page parameter 
	 * @return
	 */
	@ApiOperation(value = "View a list of available recipes",response = ResponseEntity.class)
	@GetMapping(produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<List<Recipe>> getAllRecipe(@RequestParam(value ="limit",required=false) Integer limit,@RequestParam(required=false,value="page") Integer page) {
		List<Recipe> recipeList = new ArrayList<>();
		if(limit==null && page==null) {
			recipeList = recipeService.getAllRecipes();
		}
		else {
			Page<Recipe> recipePage = recipeService.getRecipes(page, limit);
			if(recipePage!=null) {
				recipeList = recipePage.getContent();
			}
		}
		if(recipeList.isEmpty()) {
			throw new RecipeNotFoundException("No Recipe Found ");
		}else {
			return ResponseEntity.ok(recipeList);
		}

	}

	/**
	 * Get single recipe 
	 * @mapsTo /kitchenworld/api/recipes/{id}
	 * @param id
	 * @return
	 */
	@ApiOperation(value = "Get a single recipe  by id",response = ResponseEntity.class)
	@GetMapping(value = "{id}", produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Recipe> getRecipeById(@PathVariable("id") Long id){

		Recipe recipe = recipeService.getRecipe(id);

		if(recipe==null) {
			throw new RecipeNotFoundException("Recipe not found for id "+id);
		}else {
			return ResponseEntity.ok(recipe);
		}
	}

	/**
	 * Get the size of valid recipes
	 * @return
	 */
	@ApiOperation(value = "Get the total number of recipes",response = ResponseEntity.class)
	@GetMapping(value="/size" , produces=MediaType.TEXT_HTML_VALUE)
	public ResponseEntity<String> getTotalRecipes() {

		List<Recipe> recipeList = recipeService.getAllRecipes();
		if(recipeList.isEmpty()) {
			return ResponseEntity.ok(String.valueOf(0));
		}else {
			return ResponseEntity.ok(String.valueOf(recipeList.size()));
		}

	}

	/**
	 * Add a new recipe with multipart/form-data support
	 * @mapsTo  /kitchenworld/api/recipes
	 * @param recipe
	 * @param uploadFile
	 * @return
	 */
	@ApiOperation(value = "Add a new recipe along with an image",response = ResponseEntity.class)
	@PostMapping(consumes=MediaType.MULTIPART_FORM_DATA_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Object> saveRecipeWithMultiPart(@Valid @RequestPart Recipe recipe , @RequestPart("recipeImgFile") MultipartFile uploadFile){

		if(!uploadFile.isEmpty()) {
			String path = "";
			try {

				path = FileUploadUtil.uploadFile(uploadFile);
				LOGGER.info("File uploaded successfully to path "+path);
				recipe.setRcpImagePath(path);

			} catch (IOException ex) {
				LOGGER.error("File upload failed  to path "+path , ex);
				List<String>list = new ArrayList<>();
				list.add(ex.getLocalizedMessage());
				return new ResponseEntity<>(new ApiError(HttpStatus.BAD_REQUEST, "Image could not be saved: ", list),HttpStatus.BAD_REQUEST);
			}

		}
		recipe = recipeService.addRecipe(recipe);

		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
				.buildAndExpand(recipe.getRcpId()).toUri();

		LOGGER.info("Created Recipe "+recipe.toString()+" with location "+uri.toString());

		return  ResponseEntity.created(uri).body(recipe); 
	}

	/**
	 * Add a new recipe with application/json support
	 * @param recipe
	 * @return
	 */
	@ApiOperation(value = "Add a new recipe",response = ResponseEntity.class)
	@PostMapping(consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Recipe> saveRecipe(@Valid @RequestBody Recipe recipe){

		recipe = recipeService.addRecipe(recipe);

		URI uri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
				.buildAndExpand(recipe.getRcpId()).toUri();

		LOGGER.info("Created Recipe "+recipe.toString()+" with location "+uri.toString());

		return  ResponseEntity.created(uri).body(recipe); 
	}

	

	/**
	 * Delete a recipe and update table with the person deleting the  recipe 
	 * @mapsTo /kitchenworld/api/recipes/{id}
	 * @param id
	 * @param editor
	 * @return
	 */
	@ApiOperation(value = "Delete a recipe by Id",response = ResponseEntity.class)
	@DeleteMapping("{id}")
	public ResponseEntity<Void> deleteRecipe(@PathVariable("id") Long id, @RequestParam("editor") Long editor){

		recipeService.deleteRecipe(id, editor);

		return ResponseEntity.noContent().build();
	}

	/**
	 * Update a recipe with Recipe object and set the updatedby property to {principal/loggedin  user if updatedby is not passed to the api} 
	 * @mapsTo /kitchenworld/api/recipes/{id}
	 * @param id
	 * @param recipe
	 * @param principal
	 * @return
	 */
	@ApiOperation(value = "Update a recipe by id",response = ResponseEntity.class)
	@PutMapping(value="{id}", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Recipe> updateRecipe(@PathVariable("id") Long id, @Valid @RequestBody Recipe recipe, Principal principal){

		recipe.setRcpId(id);
		if(recipe.getRcpUpdatedBy()==null) {
			recipe.setRcpUpdatedBy(userService.getUserByLoginId(principal.getName()).getUsrId());
		}
		Recipe updatedRecipe = recipeService.updateRecipe(recipe);
		if(updatedRecipe==null) {
			throw new RecipeNotFoundException("Recipe with id "+id+" not found");
		}
		return ResponseEntity.ok(updatedRecipe);
	}



	/**
	 * Update  recipeid with Recipe object and image file and set the updatedby property to {principal/loggedin  user} if updatedby is not passed to the api} 
	 * /kitchenworld/api/recipes/{id}
	 * @param id
	 * @param recipe
	 * @param uploadFile
	 * @param principal
	 * @return
	 */
	@ApiOperation(value = "Update a recipe by id along with updating the recipe  image",response = ResponseEntity.class)
	@PutMapping(value="{id}", consumes=MediaType.MULTIPART_FORM_DATA_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> updateRecipe(@PathVariable("id") Long id, @Valid @RequestPart Recipe recipe, @RequestPart("recipeImgFile") MultipartFile uploadFile, Principal principal){

		recipe.setRcpId(id);
		if(recipe.getRcpUpdatedBy()==null || recipe.getRcpUpdatedBy() == 0) {
			recipe.setRcpUpdatedBy(userService.getUserByLoginId(principal.getName()).getUsrId());
		}

		if(!uploadFile.isEmpty()) {
			String path = "";
			try {

				path = FileUploadUtil.uploadFile(uploadFile);
				LOGGER.info("File uploaded successfully to path "+path);
				recipe.setRcpImagePath(path);
			} catch (IOException ex) {
				LOGGER.error("Error saving image ",ex);
				List<String>list = new ArrayList<>();
				list.add(ex.getLocalizedMessage());
				return new ResponseEntity<>(new ApiError(HttpStatus.BAD_REQUEST, "Image could not be saved: ", list),HttpStatus.BAD_REQUEST);
			}			

		}

		Recipe updatedRecipe = recipeService.updateRecipe(recipe);
		if(updatedRecipe==null) {
			throw new RecipeNotFoundException("Recipe with id "+id+" not found");
		}
		return ResponseEntity.ok(updatedRecipe);
	}


	/**
	 * Exception to handle recipe request with invalid id / no recipes in table
	 * @author Dhiraj
	 *
	 */
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public class RecipeNotFoundException extends RuntimeException{

		private static final long serialVersionUID = 1L;

		public RecipeNotFoundException(String ex) {
			super(ex);
		}

	}

}
