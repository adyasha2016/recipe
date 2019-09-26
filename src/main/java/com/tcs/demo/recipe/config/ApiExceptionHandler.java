/**
 * 
 */
package com.tcs.demo.recipe.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException.Forbidden;
import org.springframework.web.client.HttpClientErrorException.Unauthorized;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.tcs.demo.recipe.bean.ApiError;
import com.tcs.demo.recipe.controller.RecipeController.RecipeNotFoundException;
import com.tcs.demo.recipe.controller.UserController.UserNotFoundException;




/**
 * Generic Exception handler class 
 * @author Dhiraj
 *
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler{

	@Override
	protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return buildErrorResponse(new ApiError(HttpStatus.METHOD_NOT_ALLOWED, "Method  allowed: "+ex.getSupportedHttpMethods(), list));

	}

	@Override
	protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {	
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return buildErrorResponse(new ApiError(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "MediaType not supported", list));
	}


	@Override
	protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage()); 
		return buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, ex.getParameterName()+" is missing", list));
	}


	@Override
	protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException ex, HttpHeaders headers,
			HttpStatus status, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage()); 
		return buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, "Malformed Request Object", list));
	}

	@Override
	protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {	
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, "Malformed Request Object", list));
	}

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		List<String> list = new ArrayList<>();

		ex.getBindingResult().getFieldErrors().forEach(fe ->  list.add(fe.getField()+" "+fe.getDefaultMessage()));

		return	buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, "Bad Request", list));
	}


	@Override
	protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers,
			HttpStatus status, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.NOT_FOUND, ex.getHttpMethod()+" not found for requested  resource", list));
	}


	//Custom Exceptions

	@ExceptionHandler({ Forbidden.class})
	protected ResponseEntity<Object> handleForbiddenRequest(Forbidden ex, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.FORBIDDEN, "Access Denied for resource", list));
	}

	@ExceptionHandler({ Unauthorized.class })
	protected ResponseEntity<Object> handleUnauthrizedRequest(Unauthorized ex, WebRequest request) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.UNAUTHORIZED, "Unauthorized Access to resource", list));
	}

	@ExceptionHandler({UserNotFoundException.class})
	protected  ResponseEntity<Object>  handleUserNotFoundException(Exception ex,HttpServletResponse response)  {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.NOT_FOUND, "User Not found", list));
	}

	@ExceptionHandler({RecipeNotFoundException.class})
	protected  ResponseEntity<Object>  handleRecipeNotFoundException(Exception ex,HttpServletResponse response) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.NOT_FOUND, "Recipe Not found", list));
	}


	@ExceptionHandler({IllegalArgumentException.class, NullPointerException.class})
	protected  ResponseEntity<Object>  handleBadRequests(Exception ex,HttpServletResponse response) {
		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, "Bad Request", list));
	} 
	
	@ExceptionHandler(MultipartException.class)
	protected ResponseEntity<Object> handleMultiPartException(MultipartException ex ,HttpServletRequest request) {

		List<String>list = new ArrayList<>();
		list.add(ex.getLocalizedMessage());
		return	buildErrorResponse(new ApiError(HttpStatus.BAD_REQUEST, "Bad Request", list));

	}


	/**
	 * Build ResponseEntity with wrapper GenericErrorWrapper(ApiError,ApiError.status)
	 * @param error
	 * @return ResponseEntity<Object>
	 */
	private ResponseEntity<Object> buildErrorResponse(ApiError error){
		return new ResponseEntity<>(new GenericErrorWrapper(error),error.getStatus());
	}

	/**
	 * Generic wrapper  for response json error object : { "error" : { "status" : ...........} }
	 * @author Dhiraj
	 *
	 */
	public class GenericErrorWrapper{
		private ApiError error;

		public GenericErrorWrapper(ApiError apiError) {
			setError(apiError);
		}

		public ApiError getError() {
			return error;
		}

		public void setError(ApiError error) {
			this.error = error;
		}

	}
}
