package com.derekmai.aop.guard.resource.scope;

import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

/**
 * Represents a parsed form of a user's authority string, decomposed into scope type,
 * role, and resource ID.
 *
 * <p>Expected format for authority strings is: {@code ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>}</p>
 */
public class ScopeAuthority {

    private final String scopeType;
    private final String role;
    private final String resourceId;

    /**
     * Constructs a new {@code ScopeAuthority} instance.
     *
     * @param scopeType  the type of the scope (e.g., team, subteam)
     * @param role       the role granted (e.g., USER, ADMIN)
     * @param resourceId the ID of the resource the role is scoped to
     */
    public ScopeAuthority(String scopeType, String role, String resourceId) {
        this.scopeType = scopeType;
        this.role = role;
        this.resourceId = resourceId;
    }

    /**
     * Returns the type of the scope.
     *
     * @return the scope type
     */
    public String getScopeType() {
        return scopeType;
    }


    /**
     * Returns the role granted.
     *
     * @return the role
     */
    public String getRole() {
        return role;
    }


    /**
     * Returns the ID of the resource associated with the role.
     *
     * @return the resource ID
     */
    public String getResourceId() {
        return resourceId;
    }

    /**
     * Parses a collection of {@link GrantedAuthority} objects into a list of
     * {@link ScopeAuthority} objects.
     *
     * @param authorities a collection of granted authorities
     * @return a list of parsed {@code ScopeAuthority} instances
     * @throws InvalidAuthorityException if any authority string cannot be parsed
     */
    public static List<ScopeAuthority> parseAuthorities(Collection<? extends GrantedAuthority> authorities)
            throws InvalidAuthorityException {
        List<ScopeAuthority> list = new ArrayList<>();
        for (GrantedAuthority authority : authorities) {
            ScopeAuthority scopeAuthority = parseAuthority(authority.getAuthority());
            list.add(scopeAuthority);
        }
        return list;
    }

    /**
     * Parses a single authority string in the format {@code ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>}
     * into a {@link ScopeAuthority} object.
     *
     * @param authority the authority string
     * @return a {@link ScopeAuthority} object
     * @throws InvalidAuthorityException if the authority format is invalid
     */
    public static ScopeAuthority parseAuthority(String authority) throws InvalidAuthorityException {
        try {
            String[] parts = authority.substring(5).split("_", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid authority format.");
            }
            return new ScopeAuthority(parts[0].toLowerCase(), parts[1], parts[2]);
        } catch (Exception e) {
            throw new InvalidAuthorityException(String.format("Authority %s is invalid.", authority), e);
        }

    }

    /**
     * Returns a predicate that filters authorities by scope type and role membership.
     *
     * @param scopeType         the scope type to match
     * @param requiredRolesList the list of allowed roles for the scope
     * @return a predicate that evaluates to {@code true} when a {@link ScopeAuthority}
     *         matches the scope type and one of the required roles
     */
    public static Predicate<ScopeAuthority> filterAuthorityByScopeAndRoles(String scopeType,
                                                                           List<String> requiredRolesList) {
        return authority -> authority.getScopeType().equals(scopeType)
                && requiredRolesList.contains(authority.getRole());
    }
}