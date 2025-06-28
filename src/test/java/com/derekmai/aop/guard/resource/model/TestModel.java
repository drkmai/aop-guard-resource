package com.derekmai.aop.guard.resource.model;

import com.derekmai.aop.guard.resource.Identifiable;
import com.derekmai.aop.guard.resource.scope.Accessible;

public class TestModel implements Accessible, Identifiable {

    private String id;
    private TeamModel teamModel;

    public TestModel(String id, TeamModel teamModel) {
        this.id = id;
        this.teamModel = teamModel;
    }

    @Override
    public Object getId() {
        return id;
    }

    public TeamModel getTeam() {
        return teamModel;
    }
}
