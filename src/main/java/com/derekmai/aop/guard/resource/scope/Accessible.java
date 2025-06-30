package com.derekmai.aop.guard.resource.scope;

import com.derekmai.aop.guard.resource.Identifiable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static com.derekmai.aop.guard.resource.scope.ScopeAuthority.filterAuthorityByScopeAndRoles;
import static com.derekmai.aop.guard.resource.scope.ScopeAuthority.parseAuthorities;

/**
 * Interface that defines scope-based access control logic for domain objects.
 *
 * <p>Classes implementing this interface should expose getter methods that correspond
 * to scope types, such as {@code getProject()}, {@code getTeam()}, etc.
 * These scope types are matched against authorities in the format:</p>
 *
 * <pre>{@code
 * ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>
 * }</pre>
 *
 * <p>Where:
 * <ul>
 *   <li>{@code SCOPE} is the scope type (e.g., project, team)</li>
 *   <li>{@code ROLE} is the role within that scope (e.g., ADMIN, USER)</li>
 *   <li>{@code RESOURCE_ID} is the ID of the specific resource (e.g., "1234")</li>
 * </ul>
 * </p>
 *
 * <p>Scope fields must return an object implementing {@link Identifiable} so its ID can be matched
 * against the authority string.</p>
 *
 * <p>This interface is primarily intended to be used in AOP-based security mechanisms
 * to enforce access rules declaratively.</p>
 */
public interface Accessible {

    Logger log = LoggerFactory.getLogger(Accessible.class);

    /**
     * Validates if the current object is accessible by the given user, based on one or more scope-role definitions.
     *
     * <p>Access is granted if the user has at least one matching authority for any of the provided scope definitions.</p>
     *
     * @param userDetails the user attempting access
     * @param scopeRoles a list of scope definitions defining required roles per scope
     * @throws AccessDeniedException if access is not permitted
     */
    default void isAccessibleBy(UserDetails userDetails, List<ScopeDefinition> scopeRoles) {

        if (Objects.isNull(userDetails)) {
            throw new AccessDeniedException("User details is null.");
        }
        if (Objects.isNull(scopeRoles)) {
            throw new AccessDeniedException("Scope roles are null.");
        }
        if (scopeRoles.isEmpty()) {
            throw new AccessDeniedException("Scope roles are empty.");
        }
        boolean hasAtLeastOneAccess = scopeRoles.stream()
                .anyMatch(scope -> checkScopeAccess(scope, userDetails));
        if (!hasAtLeastOneAccess) {
            log.debug("User details '{}' with authorities '{}' does not have required roles for the defined scopes '{}'. "
                            + "Denying access.",
                    userDetails.getUsername(), userDetails.getAuthorities(), scopeRoles);
            throw new AccessDeniedException("User details doesn't have any of the required roles in "
                    + "any of the required scopes.");
        }
    }


    /**
     * Evaluates whether the user has access for a specific scope definition on the current object.
     *
     * <p>This involves:
     * <ul>
     *   <li>Finding the getter method for the scope (e.g., {@code getTeam()})</li>
     *   <li>Comparing the ID of the object returned by that method to the user's authority</li>
     * </ul>
     * </p>
     *
     * @param scope the scope and required roles
     * @param userDetails the user being evaluated
     * @return {@code true} if access is granted; {@code false} otherwise
     */
    default boolean checkScopeAccess(ScopeDefinition scope,
                                     UserDetails userDetails) {
        if (Objects.isNull(userDetails)) {
            throw new AccessDeniedException("User details is null.");
        }
        if (Objects.isNull(scope)) {
            throw new AccessDeniedException("Scope Definition is null.");
        }

        String scopeType = scope.scopeType();
        try {
            Method method = findMethodForScope(scopeType);
            method.setAccessible(true); // Ensure method is accessible
            Object scopeObject = method.invoke(this);

            if (Objects.isNull(scopeObject)) {
                throw new AccessDeniedException("Scope object is null.");
            }

            List<String> requiredRolesList = Arrays.asList(scope.roles());
            List<ScopeAuthority> scopeAuthorities = parseAuthorities(userDetails.getAuthorities());
            return scopeAuthorities
                    .stream()
                    .filter(filterAuthorityByScopeAndRoles(scopeType, requiredRolesList))
                    .anyMatch(authority -> checkObjectAssociation(scopeObject, authority.getResourceId()));
        } catch (InvalidAuthorityException e) {
            throw new AccessDeniedException("Access was denied because there was an invalid authority.", e);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new AccessDeniedException(String.format("Error invoking method for scope %s: ", scopeType), e);
        } catch (NoSuchMethodException | IllegalArgumentException e) {
            throw new AccessDeniedException("There was no scope type.", e);
        }
    }

    /**
     * Finds the getter method that matches the given scope type.
     *
     * <p>For example, scopeType {@code "team"} would map to {@code getTeam()}.</p>
     *
     * @param scopeType the logical scope name (case-insensitive)
     * @return a {@link Method} to access the scope object
     * @throws NoSuchMethodException if no matching method exists
     * @throws IllegalArgumentException if scope type is null or empty
     */
    default Method findMethodForScope(String scopeType) throws NoSuchMethodException, IllegalArgumentException {
        if (Objects.isNull(scopeType) || scopeType.isEmpty()) {
            throw new IllegalArgumentException("Scope type is invalid.");
        }

        String methodName = "get" + Character.toUpperCase(scopeType.charAt(0)) + scopeType.substring(1);
        try {
            return this.getClass().getDeclaredMethod(methodName);
        } catch (NoSuchMethodException e) {
            log.debug("Method {} not found for scope type {}", methodName, scopeType);
            throw e;
        }
    }

    /**
     * Checks whether the given scope object is associated with the authority's resource ID.
     *
     * <p>This comparison is done by calling {@code getId()} on the object and comparing it
     * to the resource ID in the authority.</p>
     *
     * @param scopedObject the actual domain object returned by the getter (e.g., a Project or Team)
     * @param authorityResourceId the resource ID extracted from the authority string
     * @return {@code true} if the object ID matches the authority ID; {@code false} otherwise
     */
    static boolean checkObjectAssociation(Object scopedObject, String authorityResourceId) {
        if (authorityResourceId == null) {
            return false;
        }
        if (scopedObject instanceof Identifiable) {
            Identifiable identifiable = (Identifiable) scopedObject;
            String scopeObjectId = identifiable.getId().toString();
            return authorityResourceId.equals(scopeObjectId);
        }
        log.debug("Object of type {} does not implement Identifiable", scopedObject.getClass());
        return false;
    }
}
