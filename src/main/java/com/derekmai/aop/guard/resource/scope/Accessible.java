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
import java.util.function.Predicate;

import static com.derekmai.aop.guard.resource.scope.ScopeAuthority.filterAuthorityByScopeAndRoles;
import static com.derekmai.aop.guard.resource.scope.ScopeAuthority.parseAuthorities;

/**
 * Contract interface to define scope-based access control for domain objects.
 * <p>
 * Implementing classes should expose getter methods (e.g., {@code getProject()}, {@code getTeam()})
 * that correspond to scope types used in authority strings (e.g., {@code ROLE_PROJECT_ADMIN_123}).
 * This interface evaluates whether a given {@link UserDetails} instance has access to the current object
 * based on dynamically matched scopes and roles.
 * </p>
 *
 * <p>
 * Each authority is expected to follow the format: {@code ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>},
 * where:
 * <ul>
 *   <li>{@code SCOPE} is the logical scope (e.g., project, team)</li>
 *   <li>{@code ROLE} is the user's role within that scope (e.g., ADMIN, VIEWER)</li>
 *   <li>{@code RESOURCE_ID} identifies the target resource (e.g., 123)</li>
 * </ul>
 * </p>
 *
 * <p>
 * For the object to be matched against a scope, it must return a value implementing
 * {@link com.derekmai.aop.guard.resource.Identifiable}.
 * </p>
 *
 * <p>
 * This interface is intended to be used by AOP components such as {@code GuardResourceAspect}
 * to perform authorization checks declaratively.
 * </p>
 *
 * @see com.derekmai.aop.guard.resource.Identifiable
 */
public interface Accessible {

    Logger log = LoggerFactory.getLogger(Accessible.class);

    /**
     * Evaluates whether the current object is accessible by the given {@link UserDetails}
     * based on a map of scope types and their required roles.
     *
     * @param userDetails the user whose authorities are to be evaluated
     * @param scopeRoles  a map where keys are scope types (e.g., "project") and values are required roles
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
     * Checks if the given user Details have access to the given scope definition
     *
     * @param scope       Scope definition
     * @param userDetails the user for whom access is being evaluated
     * @return a {@link boolean} indicating whether access is granted for that scope
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
     * Resolves the getter method corresponding to a given scope type.
     * For example, for scope "project", it looks for a method named {@code getProject()}.
     *
     * @param scopeType the logical name of the scope
     * @return a {@link Method} instance if found, or {@code null} otherwise
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
     * Checks whether the provided {@code scopeObject} matches the {@code resourceId}
     * from the user's authority, by comparing it to the object's ID via the {@link Identifiable} interface.
     *
     * @param scopeObject         the domain object (e.g., project, team)
     * @param authorityResourceId the resource ID from the authority
     * @return {@code true} if the resource IDs match; {@code false} otherwise
     */
    static boolean checkObjectAssociation(Object scopeObject, String authorityResourceId) {
        if (authorityResourceId == null) {
            return false;
        }
        if (scopeObject instanceof Identifiable) {
            Identifiable identifiable = (Identifiable) scopeObject;
            String scopeObjectId = identifiable.getId().toString();
            return authorityResourceId.equals(scopeObjectId);
        }
        log.debug("Object of type {} does not implement Identifiable", scopeObject.getClass());
        return false;
    }
}
