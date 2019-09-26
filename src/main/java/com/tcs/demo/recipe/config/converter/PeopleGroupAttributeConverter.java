/**
 * 
 */
package com.tcs.demo.recipe.config.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.tcs.demo.recipe.bean.Recipe.PeopleGroup;



/**
 * Converter for  Enum PeopleGroup conversions for database persistence
 * @author Dhiraj
 *
 */
@Converter(autoApply=true)
public class PeopleGroupAttributeConverter implements AttributeConverter<PeopleGroup, Integer> {
 
    @Override
    public Integer convertToDatabaseColumn(PeopleGroup attribute) {
        if (attribute == null)
            return null;
 
        switch (attribute) {
        case LESSTHANFIVE:
            return attribute.getGroupId();
 
        case FIVETOTEN:
        	 return attribute.getGroupId();
 
        case MORETHANTEN:
        	 return attribute.getGroupId();
 
        default:
            throw new IllegalArgumentException(attribute + " not supported.");
        }
    }
 
    @Override
    public PeopleGroup convertToEntityAttribute(Integer groupId) {
        if (groupId == null)
            return null;
 
        switch (groupId) {
        case 0:
            return PeopleGroup.LESSTHANFIVE;
 
        case 1:
            return PeopleGroup.FIVETOTEN;
 
        case 2:
            return PeopleGroup.MORETHANTEN;
 
        default:
            throw new IllegalArgumentException(groupId + " not supported.");
        }
    }
}