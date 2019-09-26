/**
 * 
 */
package com.tcs.demo.recipe.bean;

import java.io.Serializable;
import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;



/**
 * Bean class for Recipe
 * @author Dhiraj
 *
 */

@ApiModel
@Entity
@Table(name="recipes")
public class Recipe implements Serializable{

	private static final long serialVersionUID = 1L;

	 @ApiModelProperty(value = "The database generated recipe ID")
	@Id()
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="rcpid",updatable=false,nullable=false)
	private Long rcpId;

	 @ApiModelProperty(value = "The recipe name" , required=true)
	@NotNull
	@Column(name="rcpname")
	private String rcpName;

	 @ApiModelProperty(value = "The recipe ingredient description")
	@Lob
	@Column(name="rcpingredientdescription")
	private String rcpIngredientDescription;

	 @ApiModelProperty(value = "The recipe cooking instruction")
	@Lob
	@Column(name="rcpcookinginstruction")
	private String rcpCookingInstruction;

	 @ApiModelProperty(value = "The recipe image path")
	@Column(name="rcpimagepath")
	private String rcpImagePath;

	 @ApiModelProperty(value = "Is the recipe venetarian")
	@Column(name="rcpisvegetarian")
	private Boolean rcpIsVegetarian ;

	 @ApiModelProperty(value = "The database generated product ID",allowableValues="LESSTHANFIVE,FIVETOTEN,MORETHANTEN")
	@Column(name="rcpsuitablefor")
	private PeopleGroup rcpSuitableFor; //PeopleGroupAttributeConverter implemented with  autoApply=true

	 @ApiModelProperty(value = "The user who created the recipe")
	@Column(name="rcpcreatedby", updatable=false)
	private Long rcpCreatedBy;

	 @ApiModelProperty(value = "Time at which recipe was created",readOnly=true)
	@Column(name="rcpcreatedat", updatable=false)
	@JsonFormat(pattern="dd-MM-yyyy HH:mm")
	@CreationTimestamp
	private LocalDateTime rcpCreatedAt; //LocalDateTimeAttributeConverter implemented with autoApply = true

	 @ApiModelProperty(value = "The user who updated the recipe")
	@Column(name = "rcpupdatedby")
	private Long rcpUpdatedBy;
	
	@ApiModelProperty(value = "Time at which recipe was updated",readOnly=true)
	@Column(name="rcpupdatedat")
	@JsonFormat(pattern="dd-MM-yyyy HH:mm")
	@UpdateTimestamp
	private LocalDateTime rcpUpdatedAt;

	@ApiModelProperty(value = "If -1 consided  this  recipe deleted",allowableValues="1,-1")
	@Column(name="rcprowstate")
	private Integer rcpRowState;


	public Recipe() {
		super();
	}

	public Recipe(Long rcpId, @NotNull String rcpName, @NotNull String rcpIngredientDescription,
			String rcpCookingInstruction, String rcpImagePath, Boolean rcpIsVegetarian, PeopleGroup rcpSuitableFor,
			Long rcpCreatedBy, LocalDateTime rcpCreatedAt, Long rcpUpdatedBy, LocalDateTime rcpUpdatedAt,
			Integer rcpRowState) {
		super();
		this.rcpId = rcpId;
		this.rcpName = rcpName;
		this.rcpIngredientDescription = rcpIngredientDescription;
		this.rcpCookingInstruction = rcpCookingInstruction;
		this.rcpImagePath = rcpImagePath;
		this.rcpIsVegetarian = rcpIsVegetarian;
		this.rcpSuitableFor = rcpSuitableFor;
		this.rcpCreatedBy = rcpCreatedBy;
		this.rcpCreatedAt = rcpCreatedAt;
		this.rcpUpdatedBy = rcpUpdatedBy;
		this.rcpUpdatedAt = rcpUpdatedAt;
		this.rcpRowState = rcpRowState;
	}





	/**
	 * @return the rcpId
	 */
	public Long getRcpId() {
		return rcpId;
	}

	/**
	 * @param rcpId the rcpId to set
	 */
	public void setRcpId(Long rcpId) {
		this.rcpId = rcpId;
	}

	/**
	 * @return the rcpName
	 */
	public String getRcpName() {
		return rcpName;
	}

	/**
	 * @param rcpName the rcpName to set
	 */
	public void setRcpName(String rcpName) {
		this.rcpName = rcpName;
	}

	/**
	 * @return the rcpIngredientDescription
	 */
	public String getRcpIngredientDescription() {
		return rcpIngredientDescription;
	}

	/**
	 * @param rcpIngredientDescription the rcpIngredientDescription to set
	 */
	public void setRcpIngredientDescription(String rcpIngredientDescription) {
		this.rcpIngredientDescription = rcpIngredientDescription;
	}

	/**
	 * @return the rcpCookingInstruction
	 */
	public String getRcpCookingInstruction() {
		return rcpCookingInstruction;
	}

	/**
	 * @param rcpCookingInstruction the rcpCookingInstruction to set
	 */
	public void setRcpCookingInstruction(String rcpCookingInstruction) {
		this.rcpCookingInstruction = rcpCookingInstruction;
	}

	/**
	 * @return the rcpImagePath
	 */
	public String getRcpImagePath() {
		return rcpImagePath;
	}

	/**
	 * @param rcpImagePath the rcpImagePath to set
	 */
	public void setRcpImagePath(String rcpImagePath) {
		this.rcpImagePath = rcpImagePath;
	}

	/**
	 * @return the rcpIsVegetarian
	 */
	public Boolean getRcpIsVegetarian() {
		return rcpIsVegetarian;
	}

	/**
	 * @param rcpIsVegetarian the rcpIsVegetarian to set
	 */
	public void setRcpIsVegetarian(Boolean rcpIsVegetarian) {
		this.rcpIsVegetarian = rcpIsVegetarian;
	}

	/**
	 * @return the rcpSuitableFor
	 */
	public PeopleGroup getRcpSuitableFor() {
		return rcpSuitableFor;
	}

	/**
	 * @param rcpSuitableFor the rcpSuitableFor to set
	 */
	public void setRcpSuitableFor(PeopleGroup rcpSuitableFor) {
		this.rcpSuitableFor = rcpSuitableFor;
	}

	/**
	 * @return the rcpCreatedBy
	 */
	public Long getRcpCreatedBy() {
		return rcpCreatedBy;
	}

	/**
	 * @param rcpCreatedBy the rcpCreatedBy to set
	 */
	public void setRcpCreatedBy(Long rcpCreatedBy) {
		this.rcpCreatedBy = rcpCreatedBy;
	}

	/**
	 * @return the rcpCreatedAt
	 */
	public LocalDateTime getRcpCreatedAt() {
		return rcpCreatedAt;
	}

	/**
	 * @param rcpCreatedAt the rcpCreatedAt to set
	 */
	public void setRcpCreatedAt(LocalDateTime rcpCreatedAt) {
		this.rcpCreatedAt = rcpCreatedAt;
	}

	/**
	 * @return the rcpUpdatedBy
	 */
	public Long getRcpUpdatedBy() {
		return rcpUpdatedBy;
	}

	/**
	 * @param rcpUpdatedBy the rcpUpdatedBy to set
	 */
	public void setRcpUpdatedBy(Long rcpUpdatedBy) {
		this.rcpUpdatedBy = rcpUpdatedBy;
	}

	/**
	 * @return the rcpUpdatedAt
	 */
	public LocalDateTime getRcpUpdatedAt() {
		return rcpUpdatedAt;
	}

	/**
	 * @param rcpUpdatedAt the rcpUpdatedAt to set
	 */
	public void setRcpUpdatedAt(LocalDateTime rcpUpdatedAt) {
		this.rcpUpdatedAt = rcpUpdatedAt;
	}

	/**
	 * @return the rcpRowState
	 */
	public Integer getRcpRowState() {
		return rcpRowState;
	}

	/**
	 * @param rcpRowState the rcpRowState to set
	 */
	public void setRcpRowState(Integer rcpRowState) {
		this.rcpRowState = rcpRowState;
	}





	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((rcpCookingInstruction == null) ? 0 : rcpCookingInstruction.hashCode());
		result = prime * result + ((rcpCreatedAt == null) ? 0 : rcpCreatedAt.hashCode());
		result = prime * result + ((rcpCreatedBy == null) ? 0 : rcpCreatedBy.hashCode());
		result = prime * result + ((rcpId == null) ? 0 : rcpId.hashCode());
		result = prime * result + ((rcpImagePath == null) ? 0 : rcpImagePath.hashCode());
		result = prime * result + ((rcpIngredientDescription == null) ? 0 : rcpIngredientDescription.hashCode());
		result = prime * result + ((rcpIsVegetarian == null) ? 0 : rcpIsVegetarian.hashCode());
		result = prime * result + ((rcpName == null) ? 0 : rcpName.hashCode());
		result = prime * result + ((rcpRowState == null) ? 0 : rcpRowState.hashCode());
		result = prime * result + ((rcpSuitableFor == null) ? 0 : rcpSuitableFor.hashCode());
		result = prime * result + ((rcpUpdatedAt == null) ? 0 : rcpUpdatedAt.hashCode());
		result = prime * result + ((rcpUpdatedBy == null) ? 0 : rcpUpdatedBy.hashCode());
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
		Recipe other = (Recipe) obj;
		if (rcpCookingInstruction == null) {
			if (other.rcpCookingInstruction != null)
				return false;
		} else if (!rcpCookingInstruction.equals(other.rcpCookingInstruction))
			return false;
		if (rcpCreatedAt == null) {
			if (other.rcpCreatedAt != null)
				return false;
		} else if (!rcpCreatedAt.equals(other.rcpCreatedAt))
			return false;
		if (rcpCreatedBy == null) {
			if (other.rcpCreatedBy != null)
				return false;
		} else if (!rcpCreatedBy.equals(other.rcpCreatedBy))
			return false;
		if (rcpId == null) {
			if (other.rcpId != null)
				return false;
		} else if (!rcpId.equals(other.rcpId))
			return false;
		if (rcpImagePath == null) {
			if (other.rcpImagePath != null)
				return false;
		} else if (!rcpImagePath.equals(other.rcpImagePath))
			return false;
		if (rcpIngredientDescription == null) {
			if (other.rcpIngredientDescription != null)
				return false;
		} else if (!rcpIngredientDescription.equals(other.rcpIngredientDescription))
			return false;
		if (rcpIsVegetarian == null) {
			if (other.rcpIsVegetarian != null)
				return false;
		} else if (!rcpIsVegetarian.equals(other.rcpIsVegetarian))
			return false;
		if (rcpName == null) {
			if (other.rcpName != null)
				return false;
		} else if (!rcpName.equals(other.rcpName))
			return false;
		if (rcpRowState == null) {
			if (other.rcpRowState != null)
				return false;
		} else if (!rcpRowState.equals(other.rcpRowState))
			return false;
		if (rcpSuitableFor != other.rcpSuitableFor)
			return false;
		if (rcpUpdatedAt == null) {
			if (other.rcpUpdatedAt != null)
				return false;
		} else if (!rcpUpdatedAt.equals(other.rcpUpdatedAt))
			return false;
		if (rcpUpdatedBy == null) {
			if (other.rcpUpdatedBy != null)
				return false;
		} else if (!rcpUpdatedBy.equals(other.rcpUpdatedBy))
			return false;
		return true;
	}





	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "Recipe [rcpId=" + rcpId + ", rcpName=" + rcpName + ", rcpIngredientDescription="
				+ rcpIngredientDescription + ", rcpCookingInstruction=" + rcpCookingInstruction + ", rcpImagePath="
				+ rcpImagePath + ", rcpIsVegetarian=" + rcpIsVegetarian + ", rcpSuitableFor=" + rcpSuitableFor
				+ ", rcpCreatedBy=" + rcpCreatedBy + ", rcpCreatedAt=" + rcpCreatedAt + ", rcpUpdatedBy=" + rcpUpdatedBy
				+ ", rcpUpdatedAt=" + rcpUpdatedAt + ", rcpRowState=" + rcpRowState + "]";
	}





	/**
	 * Defines the no of people  the recipe is suitable for.
	 * 
	 *
	 */
	public enum PeopleGroup{

		LESSTHANFIVE(0),
		FIVETOTEN(1),
		MORETHANTEN(2);

		private int groupId;

		PeopleGroup(int groupId) {
			this.groupId = groupId;
		}

		/**
		 * @return the ageGroupId
		 */
		public int getGroupId() {
			return groupId;
		}

		public  String getGroup() {
			return this.name();
		}

	}

}
