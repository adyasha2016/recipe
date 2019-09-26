
var globalRecipeArray ; //global arr for access in search  and pagination operation;
var globalPageNumber = 0 ;  // global var to keep track of page number 
var globalPageLimit = 6; //global var to limit the no of recipe per page
var basicCoo =  getCookie('ba');//basic auth cookie

$(document).ready(function(){
	refreshPaginationAndImageGrid();
	
	//display object's name,cooking instruction, ingredient  matches to search input using jquery grep
	$("#searchinput").keyup(function(){
		var searchInput = $("#searchinput").val();
		
		var returnedData = $.grep(globalRecipeArray, function (element, index) {
			if(searchInput==""){
				return true;
			}else{
				if(element.rcpName.toLowerCase().includes(searchInput) || element.rcpCookingInstruction.toLowerCase().includes(searchInput)  ||  element.rcpIngredientDescription.toLowerCase().includes(searchInput)){
					return true;
				}
			}
			
		});
		refreshAndBuildImageGrid(returnedData);
	});
});


function refreshPaginationAndImageGrid(){

	buildPagination();
	showPage(globalPageNumber);
}

/**
 * Synchronous call to get the recipe object array
 * @returns
 */
function getRecipeArray(pageId,limit){
	//synchronous call to add proper pagination details

	if(pageId==undefined && limit==undefined){
		pageId=globalPageNumber;
		limit = globalPageLimit;
	}
	$.ajax({
		type: 'GET',
		url: 'api/recipes?limit='+limit+'&page='+pageId,
		dataType: 'json',
		success: function(recipeArr) {
			globalRecipeArray = recipeArr;
		},
		error : function(xhr, textStatus, errorThrown){
			if(xhr.status == 404){
				alert('No recipes found');
				globalRecipeArray = {};
			}else  if(xhr.status == 401 || xhr.status == 403){
				alert('Unauthorized to access resource');
			}else{
				alert('Error fetching recipes');
			}

		},
		headers: {
			"Authorization": "Basic " + basicCoo
		},
		async: false //most operation require the recipe array to perform certain actions and thus this call cannot be asynchronous
	});


	/*$.getJSON( "api/recipes", 
			function( recipeArr ) {
				data = recipeArr;
				console.log('Total  recipe objects'+recipeArr.length);
				refreshAndBuildImageGrid(recipeArr);

	});*/

	return globalRecipeArray;
}

/**
 * Build the image grid based on passed recipe object array.
 * @param resp
 * @returns
 */
function refreshAndBuildImageGrid(recipeArr){
	$('#grid_column').empty();

	$.each( recipeArr, function( key, value ) {
		$('#grid_column').append('<div class="img-wrap" onclick="displayRecipeModal('+value.rcpId+')">'
				+'<img src="'+ value.rcpImagePath +'" ><span style="cursor:pointer;" onclick=" deleteRecipe('+value.rcpId+',event)" title="Delete"><i class="fa fa-trash fa-lg icon-delete" aria-hidden="true"></i></span>'
				/*+'<span style="cursor:pointer;" onclick="displayRecipeModal('+value.rcpId+')" title="Edit"><i class="fa fa-pencil fa-lg icon-edit" aria-hidden="true"></i></span><span>'+value.rcpName+'</span></div>');*/
				+'<span>'+value.rcpName+'</span></div>');
	});

}
/**
 * Build the pagination palette based on No of recipe objects. Per page would contain 6 objects.
 * @param resp
 * @param limit
 * @param offset
 * @returns
 */
function buildPagination(){
	$('#pagination_id').empty();

	var size = 0; 
	$.ajax({
		type: 'GET',
		url: 'api/recipes/size',
		success: function(val) {
			size = parseInt(val);
		},
		error : function(xhr, textStatus, errorThrown){
			size = 0;
		},
		headers: {
			"Authorization": "Basic " + basicCoo
		},
		async: false 
	});
	if(size == 0)
		return;

	size = Math.ceil(size/6);  //6 default grid items in one page
	for(i=0;i<size;i++){
		if(i==0)
			$('#pagination_id').append('<li class="active" id=page'+i+'><a onclick="showPage('+i+')">'+(i+1)+'</a></li>');
		else
			$('#pagination_id').append('<li id=page'+i+'><a onclick="showPage('+i+')">'+(i+1)+'</a></li>');
	}

}


function showPage(pageId){

	globalPageNumber = pageId;
	//remove active class from all li and add to new li
	$("#pagination_id li").removeClass("active");
	$("#page"+pageId).addClass("active");

	/*
	 //handle pagination 
	 var low, high;
	//for page 1 elements 0 ---> 5 should be visible, for page 2 elements 6 --> 11 should be visible and so on... (6 elements per page)
	low = pageId*6-6;
	high = low + 5;

	var returnedData = $.grep(globalRecipeArray, function (element, index) {
		if(index >=low && index <= high){
			return true;
		}
	});*/
	
	getRecipeArray(globalPageNumber,globalPageLimit);

	refreshAndBuildImageGrid(globalRecipeArray);
}

/**
 * Send synchronous ajax request to delete the recipe{id} and refresh the recipe image grid
 * @param id
 * @returns
 */
function deleteRecipe(id,event){
	event.stopPropagation();
	editor = getCookie("ed"); //editor value  would be set in the cookie when loading home.htm from the mvccontroller
	if (confirm('Are you sure you want to delete this item ?')) {

		$.ajax({
			url: 'api/recipes/'+id+'?editor='+editor,
			type: 'DELETE',
			async: false,
			headers: {
				"Authorization": "Basic " + basicCoo
			},
			success : function(){
				alert( "Recipe "+id+" successfully deleted" );
				refreshPaginationAndImageGrid();
			},
			error : function(xhr, textStatus, errorThrown){
				if(xhr.status == 404){
					alert('No recipes found with id');
				}else  if(xhr.status == 401 || xhr.status == 403){
					alert('No permission to delete resource');
				}else{
					alert('Error in deleting the resource');
				}

			}
		});
	}
}

/**
 * Get cookie Value based on name passed
 * @param cname
 * @returns
 */
function getCookie(cname) {
	var name = cname + "=";
	var ca = document.cookie.split(';');
	for(var i = 0; i < ca.length; i++) {
		var c = ca[i];
		while (c.charAt(0) == ' ') {
			c = c.substring(1);
		}
		if (c.indexOf(name) == 0) {
			return c.substring(name.length, c.length);
		}
	}
	return "";
}

/**
 * Display the edit recipe modal window
 * @param recipeId
 * @returns
 */
function displayRecipeModal(recipeId){
	var recipeObj;
	if(recipeId==undefined || recipeId==0){
		displayRecipeModalForCreate();
		return;
	}

	$.ajax({
		url: 'api/recipes/'+recipeId,
		type: 'GET',
		async: false,
		headers: {
			"Authorization": "Basic " + basicCoo
		},
		success : function(data){
			recipeObj = data;
		}, 
		error : function(xhr, textStatus, errorThrown){
			if(xhr.status == 404){
				alert('No recipes found with id');
			}else  if(xhr.status == 401 || xhr.status == 403){
				alert('No permission to view resource');
			}else{
				alert('Error fetching the resource');
			}			
		}
	});	


	mod = $("#recipeModal");
	refreshModal(mod);

	//show the modal 
	mod.modal("show");


	//set the values for recipe obj in modal
	mod.find('#recipe-name').val(recipeObj.rcpName);
	mod.find('#recipe-description').val(recipeObj.rcpCookingInstruction);
	mod.find('#recipe-ingredient').tagsinput('add', recipeObj.rcpIngredientDescription);
	mod.find('#recipe-isveg').val(recipeObj.rcpIsVegetarian==true?"true":"false");
	mod.find('#recipe-suitablefor').val(recipeObj.rcpSuitableFor);
	mod.find('#recipe-createdby').text(recipeObj.rcpCreatedBy);
	mod.find('#recipe-createdat').text(recipeObj.rcpCreatedAt);
	mod.find('#recipe-updatedby').text(recipeObj.rcpUpdatedBy==null || recipeObj.rcpUpdatedBy==0 ?"-" :recipeObj.rcpUpdatedBy);
	mod.find('#recipe-updatedat').text(recipeObj.rcpUpdatedAt==null?"-":recipeObj.rcpUpdatedAt);
	mod.find('#recipe-img').attr("src",recipeObj.rcpImagePath);
	mod.find('#recipe-img-input').val("");

	//edit button click inside recipe modal
	mod.find('#recipe-edit-button').unbind(); //unbind the previously attached onclick. Caused button trigger to happen as many times as new  modals were opened.
	mod.find('#recipe-edit-button').on('click', function(){

		delete recipeObj.rcpImagePath;

		recipeObj.rcpName = $('#recipe-name').val();
		recipeObj.rcpCookingInstruction = $('#recipe-description').val();
		recipeObj.rcpIngredientDescription = $('#recipe-ingredient').val();
		recipeObj.rcpIsVegetarian = $('#recipe-isveg').val() == "true" ;
		recipeObj.rcpSuitableFor = $('#recipe-suitablefor').val();
		recipeObj.rcpUpdatedBy = getCookie("ed");


		//update req

		//https://stackoverflow.com/questions/49845355/spring-boot-controller-upload-multipart-and-json-to-dto/49991403

		var formData = new FormData($("#recipe-image-upload-form")[0]);
		formData.append('recipe', new Blob([JSON.stringify(recipeObj)], {
			type: "application/json"
		}));


		$.ajax({
			type: "PUT",
			enctype: 'multipart/form-data',
			url: "api/recipes/"+recipeId,
			headers: {
				"Authorization": "Basic " + basicCoo
			},
			data: formData,
			processData: false, 
			contentType: false,
			cache: false,
			success: function (data) {
				alert('Recipe updated successfully');
				refreshPaginationAndImageGrid();
			},
			error : function(xhr, textStatus, errorThrown){
				if(xhr.status == 404){
					alert('No recipes found with id');
				}else  if(xhr.status == 401 || xhr.status == 403){
					alert('No permission to update resource');
				}else{
					alert('Error updating the resource '+errorThrown);
				}	
			}
		});

	});			
	
	//delete button inside modal
	mod.find('#recipe-delete-button').unbind(); 
	mod.find('#recipe-delete-button').on('click', function(event){
		deleteRecipe(recipeId,event);
	});
}

/**
 * Modal for creation of new recipe
 * @returns
 */
function displayRecipeModalForCreate(){


	//show the modal 
	mod = $("#recipeModal");
	refreshModal(mod);
	mod.modal("show");
	//change value of edit to save
	mod.find('#recipe-edit-button').html('Save');
	//hide createdby, createdat, updatedby,  updatedat
	mod.find('#recipe-createdby').hide();
	mod.find('#recipe-createdat').hide();
	mod.find('#recipe-updatedby').hide();
	mod.find('#recipe-updatedat').hide();
	mod.find('#recipe-createdby-label').hide();
	mod.find('#recipe-createdat-label').hide();
	mod.find('#recipe-updatedby-label').hide();
	mod.find('#recipe-updatedat-label').hide();
	mod.find('#recipe-img').hide();
	mod.find('#recipe-delete-button').hide();

	//show the all mandatory  field
	mod.find('#recipe-mandatory-label').show();

	//onclose of create popup make things back to normal
	mod.on('hidden.bs.modal', function () {
		mod.find('#recipe-createdby').show();
		mod.find('#recipe-createdat').show();
		mod.find('#recipe-updatedby').show();
		mod.find('#recipe-updatedat').show();
		mod.find('#recipe-createdby-label').show();
		mod.find('#recipe-createdat-label').show();
		mod.find('#recipe-updatedby-label').show();
		mod.find('#recipe-updatedat-label').show();
		mod.find('#recipe-mandatory-label').hide();
		mod.find('#recipe-img').show();
		mod.find('#recipe-delete-button').show();
		
		refreshModal(mod);

	});

	
	//Save button functionality
	mod.find('#recipe-edit-button').unbind(); //unbind the previously attached onclick. Caused button trigger to happen as many times as new  modals were opened.
	mod.find('#recipe-edit-button').on('click', function(){
		//validations
		if($('#recipe-img-input').get(0).files.length == 0 || $('#recipe-name').val() == "" || $('#recipe-description').val() == ""  || $('#recipe-ingredient').val() == "" ){
			alert('Kindly fill all fields');
			return;
		}
		var recipeObj = new Object();
		recipeObj.rcpName = $('#recipe-name').val();
		recipeObj.rcpCookingInstruction = $('#recipe-description').val();
		recipeObj.rcpIngredientDescription = $('#recipe-ingredient').val();
		recipeObj.rcpIsVegetarian = $('#recipe-isveg').val() == "true" ;
		recipeObj.rcpSuitableFor = $('#recipe-suitablefor').val();
		recipeObj.rcpCreatedBy = getCookie("ed"); 

		var formData = new FormData($("#recipe-image-upload-form")[0]);
		formData.append('recipe', new Blob([JSON.stringify(recipeObj)], {
			type: "application/json"
		}));


		$.ajax({
			type: "POST",
			enctype: 'multipart/form-data',
			url: "api/recipes",
			headers: {
				"Authorization": "Basic " + basicCoo
			},
			data: formData,
			processData: false, 
			contentType: false,
			cache: false,
			success: function (data) {
				alert('Recipe saved  successfully');
				refreshPaginationAndImageGrid();
			},
			error : function(xhr, textStatus, errorThrown){
				if(xhr.status == 401 || xhr.status == 403){
					alert('No permission to add resource');
				}else{
					alert('Error saving resource '+errorThrown);
				}	
			}
		});
	});
	
}

/**
 * Empty the create/edit modal fields
 */
function refreshModal(mod){
	mod.find('#recipe-name').val("");
	mod.find('#recipe-description').val("");
	mod.find("#recipe-ingredient").tagsinput('removeAll');
	mod.find('#recipe-isveg').val("true");
	mod.find('#recipe-suitablefor').val("LESSTHANFIVE");
	mod.find('#recipe-createdby').text("-");
	mod.find('#recipe-createdat').text("-");
	mod.find('#recipe-updatedby').text("-");
	mod.find('#recipe-updatedat').text("-");
	mod.find('#recipe-img').attr("src","");
	mod.find('#recipe-img-input').val("");
}