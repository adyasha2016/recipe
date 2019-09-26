/**
 * 
 */
package com.tcs.demo.recipe.bean;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonFormat;

/**
 * Generalized Error class to represent API error 
 * @author Dhiraj
 *
 */
public class ApiError implements Serializable {
	
	private static final long serialVersionUID = 1L;

	private HttpStatus status;
	
	 @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
	private Date timestamp;
	
	private String message;
	
	private List<String> debugMessage;
	
	private ApiError() {
		timestamp = new Date();
	}

	public ApiError(HttpStatus status){
		this();
		this.status = status;
	}
	
	public ApiError(HttpStatus status, List<String> ex) {
	       this();
	       this.status = status;
	       this.message = "Error occured";
	       this.debugMessage = ex;
	   }
	
	public ApiError(HttpStatus status,String message, List<String> ex) {
	       this();
	       this.status = status;
	       this.message = message;
	       this.debugMessage = ex;
	   }

	/**
	 * @return the status
	 */
	public HttpStatus getStatus() {
		return status;
	}

	/**
	 * @param status the status to set
	 */
	public void setStatus(HttpStatus status) {
		this.status = status;
	}

	/**
	 * @return the timestamp
	 */
	public Date getTimestamp() {
		return timestamp;
	}

	/**
	 * @param timestamp the timestamp to set
	 */
	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * @param message the message to set
	 */
	public void setMessage(String message) {
		this.message = message;
	}

	/**
	 * @return the debugMessage
	 */
	public  List<String>  getDebugMessage() {
		return debugMessage;
	}

	/**
	 * @param debugMessage the debugMessage to set
	 */
	public void setDebugMessage( List<String>  debugMessage) {
		this.debugMessage = debugMessage;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((debugMessage == null) ? 0 : debugMessage.hashCode());
		result = prime * result + ((message == null) ? 0 : message.hashCode());
		result = prime * result + ((status == null) ? 0 : status.hashCode());
		result = prime * result + ((timestamp == null) ? 0 : timestamp.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ApiError other = (ApiError) obj;
		if (debugMessage == null) {
			if (other.debugMessage != null)
				return false;
		} else if (!debugMessage.equals(other.debugMessage))
			return false;
		if (message == null) {
			if (other.message != null)
				return false;
		} else if (!message.equals(other.message))
			return false;
		if (status != other.status)
			return false;
		if (timestamp == null) {
			if (other.timestamp != null)
				return false;
		} else if (!timestamp.equals(other.timestamp))
			return false;
		return true;
	}
	
	
}
