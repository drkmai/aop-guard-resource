package com.derekmai.aop.guard.resource;

import com.derekmai.aop.guard.resource.scope.Accessible;
import com.derekmai.aop.guard.resource.scope.ScopeDefinition;
import com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver;
import com.derekmai.aop.guard.resource.user.UserDetailsResolver;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Aspect class responsible for enforcing security access control on methods
 * annotated with {@link GuardResource}.
 *
 * <p>
 * This aspect intercepts method calls and performs authorization checks
 * against the scopes defined in the {@code @GuardResource} annotation.
 * It validates that the current user has sufficient roles and access rights
 * to the resource(s) returned by the method.
 * </p>
 *
 * <p>
 * User details are resolved either from the security context or from method parameters,
 * depending on the configuration in the scope definitions.
 * </p>
 *
 * <p>
 * If access is denied, an {@link AccessDeniedException} is thrown,
 * preventing further execution or returning the secured resource.
 * </p>
 */
@Component
public class GuardResourceAspect {

  private final Logger log = LoggerFactory.getLogger(GuardResourceAspect.class);

  private final ApplicationContext context;

  /**
   * Constructs the aspect with the given Spring application context.
   *
   * @param context the application context used to resolve beans such as user resolvers
   */
  public GuardResourceAspect(ApplicationContext context) {
    this.context = context;
  }

  /**
   * Intercepts method invocations annotated with {@link GuardResource} to perform access control.
   *
   * <p>
   * It extracts the {@code GuardResource} annotation, groups scopes by their user resolution
   * strategy, resolves the current user details accordingly, and validates access on the
   * method result.
   * </p>
   *
   * <p>
   * Supports method results that are either single objects or iterables of objects implementing
   * the {@link Accessible} interface.
   * </p>
   *
   * @param invocation the intercepted method invocation
   * @return the original method result if access is granted
   * @throws Throwable if access is denied or any underlying method throws an exception
   */
  public Object guardResource(MethodInvocation invocation) throws Throwable {
    try {
      Method method = invocation.getMethod();
      log.info("Guarding method: {}", method.getName());

      Object result = invocation.proceed();
      if (Objects.isNull(result)) {
        log.warn("Method returned null result");
        return null;
      }

      GuardResource guardResource = method.getAnnotation(GuardResource.class);
      if (guardResource == null) {
        throw new AccessDeniedException("Missing @GuardResource annotation");
      }

      ScopeDefinition[] scopes = guardResource.scopes();
      Map<ScopeKey, List<ScopeDefinition>> groupedScopes = groupScopesByResolution(scopes);

      boolean allGroupedScopedHaveAllowedAccess = true;
      for (Map.Entry<ScopeKey, List<ScopeDefinition>> entry : groupedScopes.entrySet()) {
        ScopeKey key = entry.getKey();
        UserDetails userDetails = resolveUserDetails(key, method, invocation.getArguments());

        if (!validateScopes(entry.getValue(), userDetails, result)) {
          allGroupedScopedHaveAllowedAccess = false;
          break; // Fail if any scope group denies access
        }
      }

      if (!allGroupedScopedHaveAllowedAccess) {
        throw new AccessDeniedException("Access denied by one or more scope groups");
      }

      return result;

    } catch (AccessDeniedException e) {
      log.warn("Access denied: {}", e.getMessage());
      throw e;
    } catch (Exception e) {
      log.warn("Unexpected error during security check", e);
      throw e;
    } catch (Error e) {
      log.warn("Unexpected runtime error during security check", e);
      throw e;
    }
  }

  /**
   * Groups the given array of {@link ScopeDefinition} by user resolution parameters:
   * user ID parameter name and user resolver class.
   *
   * @param scopes array of scope definitions from the annotation
   * @return a map grouping scopes by their {@link ScopeKey}
   */
  private Map<ScopeKey, List<ScopeDefinition>> groupScopesByResolution(ScopeDefinition[] scopes) {
    return Arrays.stream(scopes)
            .collect(Collectors.groupingBy(
                    scope -> new ScopeKey(scope.userIdParam(), scope.userResolver())
            ));
  }

  /**
   * Resolves {@link UserDetails} based on the given {@link ScopeKey} configuration,
   * the intercepted method, and its arguments.
   *
   * <p>
   * If a user ID parameter and a custom resolver are configured, attempts to resolve
   * user details from the method parameter; otherwise, resolves from the Spring Security context.
   * </p>
   *
   * @param key the scope key defining user resolution parameters
   * @param method the intercepted method
   * @param arguments the method arguments
   * @return the resolved user details
   * @throws AccessDeniedException if user details cannot be resolved
   */
  private UserDetails resolveUserDetails(ScopeKey key, Method method, Object[] arguments) throws AccessDeniedException {
    try {
      if (!key.userIdParam.isEmpty() && !key.userResolver.equals(DefaultUserDetailsResolver.class)) {
        return resolveUserDetailsFromParam(method, arguments, key);
      } else {
        return resolveDefaultUserDetails();
      }
    } catch (Exception e) {
      log.warn("Failed to resolve user details: {}", e.getMessage());
      throw new AccessDeniedException("User details could not be resolved.");
    }
  }

  /**
   * Resolves user details by extracting the parameter specified by {@code userIdParam}
   * from the intercepted method arguments and using the configured {@link UserDetailsResolver}.
   *
   * @param method the intercepted method
   * @param arguments the method arguments
   * @param key the scope key containing user resolution info
   * @return resolved user details
   * @throws AccessDeniedException if the user ID parameter is not found or resolution fails
   */
  private UserDetails resolveUserDetailsFromParam(Method method, Object[] arguments, ScopeKey key) throws AccessDeniedException {
    for (int i = 0; i < method.getParameterCount(); i++) {
      Parameter parameter = method.getParameters()[i];
      if (parameter.getName().equals(key.userIdParam)) {
        Object userId = arguments[i];
        UserDetailsResolver userDetailsResolver = context.getBean(key.userResolver);
        return userDetailsResolver.resolve(userId);
      }
    }
    throw new AccessDeniedException("User id param wasn't found in method parameters.");
  }

  /**
   * Resolves user details from the Spring Security context using
   * the default {@link DefaultUserDetailsResolver}.
   *
   * @return resolved user details
   */
  private UserDetails resolveDefaultUserDetails() {
    return context.getBean(DefaultUserDetailsResolver.class)
            .resolve(SecurityContextHolder.getContext().getAuthentication());
  }

  /**
   * Validates the list of scopes against the user details and the resource(s) returned by the method.
   *
   * <p>
   * If the result is an {@link Iterable}, checks access for each item individually.
   * Otherwise, checks access for the single object.
   * </p>
   *
   * @param scopes the list of scopes to validate
   * @param userDetails the user details to validate access for
   * @param result the method result object(s)
   * @return true if access is granted for all checked scopes, false otherwise
   */
  private boolean validateScopes(List<ScopeDefinition> scopes, UserDetails userDetails, Object result) {
    if (result instanceof Iterable<?>) {
      boolean ret = true;
      for (Object item : (Iterable<?>) result) {
        if (scopes.stream().noneMatch(scope -> validateSingleObjectForScope(scope, item, userDetails))) {
          ret = false;
        }
      }
      return ret;
    } else {
      return scopes.stream().anyMatch(scope -> validateSingleObjectForScope(scope, result, userDetails));
    }
  }

  /**
   * Validates access for a single scope on a single resource object.
   *
   * <p>
   * The resource object must implement {@link Accessible} interface.
   * </p>
   *
   * @param scope the scope definition to validate
   * @param result the resource object to check access against
   * @param userDetails the user details
   * @return true if access is granted, false otherwise
   * @throws AccessDeniedException if the resource object is invalid
   */
  private boolean validateSingleObjectForScope(ScopeDefinition scope, Object result, UserDetails userDetails) {
    if (result instanceof Accessible) {
      Accessible accessible = (Accessible) result;
      Map<String, String[]> scopeRoles = new HashMap<>();
      scopeRoles.put(scope.scopeType(), scope.roles());
      return accessible.isAccessibleBy(userDetails, scopeRoles);
    } else {
      log.warn("Resource does not implement Accessible interface");
      throw new AccessDeniedException("Invalid resource type for scope " + scope.scopeType());
    }
  }

  /**
   * Helper class representing a key to group scopes by user resolution parameters.
   */
  private static class ScopeKey {
    final String userIdParam;
    final Class<? extends UserDetailsResolver> userResolver;

    ScopeKey(String userIdParam, Class<? extends UserDetailsResolver> userResolver) {
      this.userIdParam = userIdParam;
      this.userResolver = userResolver;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      ScopeKey scopeKey = (ScopeKey) o;
      return Objects.equals(userIdParam, scopeKey.userIdParam) &&
              Objects.equals(userResolver, scopeKey.userResolver);
    }

    @Override
    public int hashCode() {
      return Objects.hash(userIdParam, userResolver);
    }
  }
}
