package com.derekmai.aop.guard.resource.scope;

import com.derekmai.aop.guard.resource.Identifiable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

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
   * @return {@code true} if <b>any</b> of the specified scope-role conditions match the user's authorities
   */
  default boolean isAccessibleBy(UserDetails userDetails, Map<String, String[]> scopeRoles) {
    if (userDetails == null || scopeRoles == null || scopeRoles.isEmpty()) {
      return false;
    }
    return scopeRoles.entrySet().stream()
        .map(entry -> createScopeAccessCheck(entry, userDetails))
        .anyMatch(ScopeAccessCheck::hasAccess);
  }

  /**
   * Builds a {@link ScopeAccessCheck} for a given scope type and associated roles
   * by invoking the matching getter method from the current object.
   *
   * @param entry       a map entry containing the scope type and required roles
   * @param userDetails the user for whom access is being evaluated
   * @return a {@link ScopeAccessCheck} indicating whether access is granted for that scope
   */
  default ScopeAccessCheck createScopeAccessCheck(Map.Entry<String, String[]> entry,
                                          UserDetails userDetails) {
    String scopeType = entry.getKey();
    String[] requiredRoles = entry.getValue();

    Method method = findMethodForScope(scopeType);
    if (method == null) {
      log.debug("No method found for scope type: {}", scopeType);
      return new ScopeAccessCheck(false);
    }

    try {
      method.setAccessible(true); // Ensure method is accessible
      Object scopeObject = method.invoke(this);
      return new ScopeAccessCheck(
          checkScopeAccess(userDetails, scopeObject, scopeType, requiredRoles)
      );
    } catch (Exception e) {
      log.debug("Error invoking method for scope {}: {}", scopeType, e.getMessage());
      return new ScopeAccessCheck(false);
    }
  }

  /**
   * Wrapper class for a boolean result representing whether access is granted or denied.
   */
  class ScopeAccessCheck {
    private final boolean hasAccess;

    ScopeAccessCheck(boolean hasAccess) {
      this.hasAccess = hasAccess;
    }

    public boolean hasAccess() {
      return hasAccess;
    }
  }

  /**
   * Resolves the getter method corresponding to a given scope type.
   * For example, for scope "project", it looks for a method named {@code getProject()}.
   *
   * @param scopeType the logical name of the scope
   * @return a {@link Method} instance if found, or {@code null} otherwise
   */
  default Method findMethodForScope(String scopeType) {
    if (Objects.isNull(scopeType) || scopeType.isEmpty()) {
      return null;
    }

    String methodName = "get" + Character.toUpperCase(scopeType.charAt(0)) + scopeType.substring(1);
    try {
      return this.getClass().getDeclaredMethod(methodName);
    } catch (NoSuchMethodException e) {
      log.debug("Method {} not found for scope type {}", methodName, scopeType);
      return null;
    }
  }

  /**
   * Verifies if the given {@link UserDetails} has the required role and resource access
   * for a given scope object.
   *
   * @param userDetails       the user whose authorities are evaluated
   * @param scopeObject       the object representing the target scope
   * @param scopeType         the type of scope being checked (e.g., "project")
   * @param requiredRoles     the roles required for access
   * @return {@code true} if the user has at least one matching authority and resource association
   */
  static boolean checkScopeAccess(UserDetails userDetails, Object scopeObject,
                                   String scopeType, String[] requiredRoles) {

    if (userDetails == null || scopeObject == null || scopeType == null || requiredRoles == null) {
      return false;
    }

    return parseAuthorities(userDetails.getAuthorities())
        .stream()
        .filter(authority -> authority.getScopeType().equals(scopeType))
        .anyMatch(authority ->
            Arrays.asList(requiredRoles).contains(authority.getRole()) &&
                checkObjectAssociation(scopeObject, authority.getResourceId())
        );
  }

  /**
   * Parses a collection of {@link GrantedAuthority} into a list of {@link ScopeAuthority}
   * by extracting scope, role, and resource ID.
   *
   * @param authorities the user's authorities to be parsed
   * @return a list of valid {@link ScopeAuthority} instances
   */
  static List<ScopeAuthority> parseAuthorities(
      Collection<? extends GrantedAuthority> authorities) {
    return authorities.stream()
        .map(authority -> parseAuthority(authority.getAuthority()))
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

  /**
   * Parses a single authority string in the format {@code ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>}
   * into a {@link ScopeAuthority} object.
   *
   * @param authority the authority string
   * @return a {@link ScopeAuthority} if the format is valid, or {@code null} otherwise
   */
  static ScopeAuthority parseAuthority(String authority) {
    if (authority == null || !authority.startsWith("ROLE_")) {
      return null;
    }

    String[] parts = authority.substring(5).split("_", 3);
    if (parts.length != 3) {
      log.debug("Invalid authority format: {}", authority);
      return null;
    }

    return new ScopeAuthority(
        parts[0].toLowerCase(),
        parts[1],
        parts[2]
    );
  }

  /**
   * Parsed representation of a user's authority string, broken into scope type, role, and resource ID.
   */
  class ScopeAuthority {
    private final String scopeType;
    private final String role;
    private final String resourceId;

    ScopeAuthority(String scopeType, String role, String resourceId) {
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
