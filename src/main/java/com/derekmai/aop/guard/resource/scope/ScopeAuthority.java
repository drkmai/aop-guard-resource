package com.derekmai.aop.guard.resource.scope;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

/**
 * Parsed representation of a user's authority string, broken into scope type, role, and resource ID.
 */
public class ScopeAuthority {

    private static final Logger log = LoggerFactory.getLogger(ScopeAuthority.class);

    private final String scopeType;
    private final String role;
    private final String resourceId;

    public ScopeAuthority(String scopeType, String role, String resourceId) {
        this.scopeType = scopeType;
        this.role = role;
        this.resourceId = resourceId;
    }

    public String getScopeType() {
        return scopeType;
    }

    public String getRole() {
        return role;
    }

    public String getResourceId() {
        return resourceId;
    }

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
     * @return a {@link ScopeAuthority} if the format is valid, or {@code null} otherwise
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
    
    public static Predicate<ScopeAuthority> filterAuthorityByScopeAndRoles(String scopeType,
                                                                           List<String> requiredRolesList) {
        return authority -> authority.getScopeType().equals(scopeType)
                && requiredRolesList.contains(authority.getRole());
    }
}