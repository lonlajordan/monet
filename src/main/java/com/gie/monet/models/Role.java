package com.gie.monet.models;

public enum Role {
    ROLE_GIE_ADMIN("ADMINISTRATEUR"),
    ROLE_AGENCE_CODE("AGENCE CODE"),
    ROLE_AGENCE_CARTE("AGENCE CARTE");

    private final String displayValue;

    Role(String displayValue) {
        this.displayValue = displayValue;
    }

    public String getDisplayValue() {
        return displayValue;
    }
}
