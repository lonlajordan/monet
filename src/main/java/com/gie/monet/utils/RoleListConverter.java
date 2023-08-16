package com.gie.monet.utils;

import com.gie.monet.models.Role;
import org.apache.commons.lang3.StringUtils;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Converter
public class RoleListConverter implements AttributeConverter<List<Role>, String> {
    @Override
    public String convertToDatabaseColumn(List<Role> roles) {
        return roles.stream().map(Role::name).collect(Collectors.joining(";"));
    }

    @Override
    public List<Role> convertToEntityAttribute(String s) {
        Role[] values = Role.values();
        List<Role> privileges = new ArrayList<>();
        for(Role value: values){
            if(StringUtils.contains(s, value.name())) privileges.add(value);
        }
        return privileges;
    }
}
