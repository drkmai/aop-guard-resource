package com.derekmai.aop.guard.resource.scope;

import com.derekmai.aop.guard.resource.user.UserDetailsResolver;

import java.util.Objects;

/**
 * Represents a unique combination of user resolution logic based on a user ID parameter and a resolver class.
 *
 * <p>This class is typically used to group {@link ScopeDefinition}s that require user-based access control
 * via a {@link UserDetailsResolver}. It enables consistent identification of scopes that rely on the same
 * user resolution strategy.</p>
 *
 * <p>Two instances of this class are considered equal if both the {@code userIdParam} and {@code userResolver}
 * are equal.</p>
 *
 * @see ScopeDefinition
 * @see UserDetailsResolver
 */
public class UserResolution {

    private final String userIdParam;
    private final Class<? extends UserDetailsResolver> userResolver;

    /**
     * Constructs a new {@code UserResolution} with the given parameter and resolver class.
     *
     * @param userIdParam   the parameter name used to extract the user ID from the method arguments
     * @param userResolver  the class used to resolve a {@link org.springframework.security.core.userdetails.UserDetails}
     *                      object from the user ID
     * @throws NullPointerException if any of the parameters are {@code null}
     */
    public UserResolution(String userIdParam, Class<? extends UserDetailsResolver> userResolver) {
        this.userIdParam = Objects.requireNonNull(userIdParam,
                "User Id parameter is required when creating an instance of UserResolution");
        this.userResolver = Objects.requireNonNull(userResolver,
                "User Resolver class is required when creating an instance of UserResolution");
    }

    /**
     * Returns the name of the parameter used to identify the user ID.
     *
     * @return the user ID parameter name
     */
    public String getUserIdParam() {
        return userIdParam;
    }

    /**
     * Returns the resolver class responsible for converting a user ID to a {@link org.springframework.security.core.userdetails.UserDetails}.
     *
     * @return the user resolver class
     */
    public Class<? extends UserDetailsResolver> getUserResolver() {
        return userResolver;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserResolution)) return false;

        UserResolution that = (UserResolution) o;
        return Objects.equals(userIdParam, that.userIdParam)
                && Objects.equals(userResolver, that.userResolver);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userIdParam, userResolver);
    }
}
