package com.derekmai.aop.guard.resource.scope;

import com.derekmai.aop.guard.resource.user.UserDetailsResolver;

import java.util.Objects;

/**
 * Helper class representing a key to group scopes by user resolution parameters.
 */
public class UserResolution {

    private final String userIdParam;
    private final Class<? extends UserDetailsResolver> userResolver;

    /**
     * All params constructor.
     * @param userIdParam user id parameter that will be used for obtaining a valid user.
     * @param userResolver User resolver that will be used for resolving the user identity based on User ID's parameter.
     */
    public UserResolution(String userIdParam, Class<? extends UserDetailsResolver> userResolver) {
        this.userIdParam = Objects.requireNonNull(userIdParam,
                "User Id parameter is required when creating an instance of ScopeKey");
        this.userResolver = Objects.requireNonNull(userResolver,
                "User Resolver class is required when creating an instance of ScopeKey");
    }

    public String getUserIdParam() {
        return userIdParam;
    }

    public Class<? extends UserDetailsResolver> getUserResolver() {
        return userResolver;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserResolution)) return false;

        UserResolution userResolution = (UserResolution) o;
        return Objects.equals(userIdParam, userResolution.userIdParam)
                && Objects.equals(userResolver, userResolution.userResolver);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userIdParam, userResolver);
    }
}