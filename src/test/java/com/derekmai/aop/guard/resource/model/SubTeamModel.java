package com.derekmai.aop.guard.resource.model;

import com.derekmai.aop.guard.resource.Identifiable;
import com.derekmai.aop.guard.resource.scope.Accessible;

public class SubTeamModel implements Accessible, Identifiable {

    private String id;
    private TeamModel teamModel;

    public SubTeamModel(String id,TeamModel team) {
        this.id = id;
        this.teamModel = team;
    }

    @Override
    public Object getId() {
        return id;
    }

    public TeamModel getTeam() {
        return teamModel;
    }

    public SubTeamModel getSubteam() {
        return this;
    }
}
