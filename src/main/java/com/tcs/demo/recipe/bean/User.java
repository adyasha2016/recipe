/**
 * 
 */
package com.tcs.demo.recipe.bean;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * Bean class for users
 * @table kitchen.users
 * @author Dhiraj
 *
 */
@Entity
@Table(name="users")
public class User implements Serializable{

	private static final long serialVersionUID = 1L;

	@Id()
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="usrid",updatable=false,nullable=false)
	private Long usrId;

	@NotNull
	@NotEmpty
	@Column(name="usrname",nullable=false)
	private String usrName;

	@NotNull
	@NotEmpty
	@Column(name="usrloginid",unique=true,nullable=false)
	private String usrLoginId;

	@NotNull
	@NotEmpty
	@Column(name="usrpassword",nullable=false)
	private String usrPassword;

	@Column(name="usrisadmin")
	private Boolean usrIsAdmin ;//default value in case not set by api calls

	@Column(name="usrrowstate")
	private Integer usrRowState ; //default value in case not set by api calls


	public User() {
		super();
	}

	public User(Long usrId, @NotNull String usrName, @NotNull String usrLoginId, @NotNull String usrPassword,
			Boolean usrIsAdmin, Integer usrRowState) {
		super();
		this.usrId = usrId;
		this.usrName = usrName;
		this.usrLoginId = usrLoginId;
		this.usrPassword = usrPassword;
		this.usrIsAdmin = usrIsAdmin;
		this.usrRowState = usrRowState;
	}



	/**Unique user id
	 * @return the usrId
	 */
	public Long getUsrId() {
		return usrId;
	}
	/**
	 * @param usrId the usrId to set
	 */
	public void setUsrId(Long usrId) {
		this.usrId = usrId;
	}
	/** User's full name
	 * @return the usrName
	 */
	public String getUsrName() {
		return usrName;
	}
	/**
	 * @param usrName the usrName to set
	 */
	public void setUsrName(String usrName) {
		this.usrName = usrName;
	}
	/** User's unique login id
	 * @return the usrLoginId
	 */
	public String getUsrLoginId() {
		return usrLoginId;
	}
	/**
	 * @param usrLoginId the usrLoginId to set
	 */
	public void setUsrLoginId(String usrLoginId) {
		this.usrLoginId = usrLoginId;
	}
	/**User's password
	 * @return the usrPassword
	 */
	@JsonIgnore //don't write password to json objects returned by api
	public String getUsrPassword() {
		return usrPassword;
	}
	/**
	 * @param usrPassword the usrPassword to set
	 */
	@JsonProperty
	public void setUsrPassword(String usrPassword) {
		this.usrPassword = usrPassword;
	}
	/** Is user admin
	 * @return the usrIsAdmin (true-1 / false-0)
	 */
	public Boolean getUsrIsAdmin() {
		return usrIsAdmin;
	}
	/**
	 * @param usrIsAdmin the usrIsAdmin to set
	 */
	public void setUsrIsAdmin(Boolean usrIsAdmin) {
		this.usrIsAdmin = usrIsAdmin;
	}
	/**Is user valid
	 * @return the usrrowstate(1-true / 0-false)
	 */
	public Integer getUsrrowstate() {
		return usrRowState;
	}
	/**
	 * @param usrrowstate the usrrowstate to set
	 */
	public void setUsrrowstate(Integer usrRowState) {
		this.usrRowState = usrRowState;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((usrId == null) ? 0 : usrId.hashCode());
		result = prime * result + ((usrIsAdmin == null) ? 0 : usrIsAdmin.hashCode());
		result = prime * result + ((usrLoginId == null) ? 0 : usrLoginId.hashCode());
		result = prime * result + ((usrName == null) ? 0 : usrName.hashCode());
		result = prime * result + ((usrPassword == null) ? 0 : usrPassword.hashCode());
		result = prime * result + ((usrRowState == null) ? 0 : usrRowState.hashCode());
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		User other = (User) obj;
		if (usrId == null) {
			if (other.usrId != null)
				return false;
		} else if (!usrId.equals(other.usrId))
			return false;
		if (usrIsAdmin == null) {
			if (other.usrIsAdmin != null)
				return false;
		} else if (!usrIsAdmin.equals(other.usrIsAdmin))
			return false;
		if (usrLoginId == null) {
			if (other.usrLoginId != null)
				return false;
		} else if (!usrLoginId.equals(other.usrLoginId))
			return false;
		if (usrName == null) {
			if (other.usrName != null)
				return false;
		} else if (!usrName.equals(other.usrName))
			return false;
		if (usrPassword == null) {
			if (other.usrPassword != null)
				return false;
		} else if (!usrPassword.equals(other.usrPassword))
			return false;
		if (usrRowState == null) {
			if (other.usrRowState != null)
				return false;
		} else if (!usrRowState.equals(other.usrRowState))
			return false;
		return true;
	}
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "User [usrId=" + usrId + ", usrName=" + usrName + ", usrLoginId=" + usrLoginId + ", usrPassword="
				+ usrPassword + ", usrIsAdmin=" + usrIsAdmin + ", usrrowstate=" + usrRowState + "]";
	}




}
