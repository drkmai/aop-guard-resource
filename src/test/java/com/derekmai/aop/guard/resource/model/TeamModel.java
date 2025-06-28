package com.derekmai.aop.guard.resource.model;

import com.derekmai.aop.guard.resource.Identifiable;

public class TeamModel implements Identifiable {

    private String id;

    public TeamModel(String id) {
        this.id = id;
    }

    @Override
    public Object getId() {
        return id;
    }
}