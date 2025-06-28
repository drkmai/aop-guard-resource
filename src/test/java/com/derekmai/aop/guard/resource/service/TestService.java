package com.derekmai.aop.guard.resource.service;

import com.derekmai.aop.guard.resource.GuardResource;
import com.derekmai.aop.guard.resource.scope.ScopeDefinition;

public class TestService {

    @GuardResource(scopes = {
            @ScopeDefinition(scopeType = "team", roles = {"USER"})
    })
    public Object securedMethod() {
        return null;
    }

    @GuardResource(scopes = {
            @ScopeDefinition(scopeType = "subteam", roles = {"USER"}),
            @ScopeDefinition(scopeType = "team", roles = {"ADMIN"})
    })
    public Object securedMethod2() {
        return null;
    }

    @GuardResource(scopes = {
            @ScopeDefinition(scopeType = "subteam", roles = {"USER"}),
            @ScopeDefinition(scopeType = "team", roles = {"ADMIN"}),
            @ScopeDefinition(scopeType = "team", roles = {"ADMIN"},
                    userIdParam = "arg0", userResolver = StubUserDetailsResolver.class)
    })
    public Object securedMethod3(String arg0) {
        return null;
    }

    public Object securedMethod4() {
        return null;
    }
}
