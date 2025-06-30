package com.derekmai.aop.guard.resource;

import com.derekmai.aop.guard.resource.scope.Accessible;
import com.derekmai.aop.guard.resource.scope.ScopeDefinition;
import com.derekmai.aop.guard.resource.scope.UserResolution;
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
        log.warn("Method returned null result. There's nothing to Guard.");
        return null;
      }

      GuardResource guardResource = method.getAnnotation(GuardResource.class);
      if (guardResource == null) {
        throw new AccessDeniedException("Missing @GuardResource annotation");
      }

      ScopeDefinition[] scopes = guardResource.scopes();
      Map<UserResolution, List<ScopeDefinition>> groupedScopes = groupScopesDefinitionsByUserResolution(scopes);

      for (Map.Entry<UserResolution, List<ScopeDefinition>> entry : groupedScopes.entrySet()) {
        UserResolution key = entry.getKey();
        UserDetails userDetails = resolveUserDetails(key, method, invocation.getArguments());
        validateScopes(entry.getValue(), userDetails, result);
      }

      return result;

    } catch (Exception e) {
      log.warn("Access denied: {}", e.getMessage());
      throw e;
    }
  }

  /**
   * Groups the given array of {@link ScopeDefinition} by user resolution parameters:
   * user ID parameter name and user resolver class.
   *
   * @param scopes array of scope definitions from the annotation
   * @return a map grouping scopes by their {@link UserResolution}
   */
  private Map<UserResolution, List<ScopeDefinition>> groupScopesDefinitionsByUserResolution(ScopeDefinition[] scopes) {
    return Arrays.stream(scopes)
            .collect(Collectors.groupingBy(
                    scope -> new UserResolution(scope.userIdParam(), scope.userResolver())
            ));
  }

  /**
   * Resolves {@link UserDetails} based on the given {@link UserResolution} configuration,
   * the intercepted method, and its arguments.
   *
   * <p>
   * If a user ID parameter and a custom resolver are configured, attempts to resolve
   * user details from the method parameter; otherwise, resolves from the Spring Security context.
   * </p>
   *
   * @param userResolution the user resolution
   * @param method the intercepted method
   * @param arguments the method arguments
   * @return the resolved user details
   * @throws AccessDeniedException if user details cannot be resolved
   */
  private UserDetails resolveUserDetails(UserResolution userResolution, Method method,
                                         Object[] arguments) throws AccessDeniedException {
    try {
      if (!userResolution.getUserIdParam().isEmpty()
              && !userResolution.getUserResolver().equals(DefaultUserDetailsResolver.class)) {
        return resolveUserDetailsFromParam(userResolution, method, arguments);
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
   * @param userResolution the User Resolution
   * @return resolved user details
   * @throws AccessDeniedException if the user ID parameter is not found or resolution fails
   */
  private UserDetails resolveUserDetailsFromParam(UserResolution userResolution, Method method,
                                                   Object[] arguments) throws AccessDeniedException {
    for (int i = 0; i < method.getParameterCount(); i++) {
      Parameter parameter = method.getParameters()[i];
      if (parameter.getName().equals(userResolution.getUserIdParam())) {
        Object userId = arguments[i];
        UserDetailsResolver userDetailsResolver = context.getBean(userResolution.getUserResolver());
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
   */
  private void validateScopes(List<ScopeDefinition> scopes, UserDetails userDetails, Object result) {
    if (result instanceof Iterable<?>) {
      for (Object item : (Iterable<?>) result) {
        validateSingleObjectForScopes(scopes, item, userDetails);
      }
    } else {
      validateSingleObjectForScopes(scopes, result, userDetails);
    }
  }

  /**
   * Validates access for a single scope on a single resource object.
   *
   * <p>
   * The resource object must implement {@link Accessible} interface.
   * </p>
   *
   * @param scopes the list of scopes to validate
   * @param result the resource object to check access against
   * @param userDetails the user details
   * @throws AccessDeniedException if the resource object is invalid
   */
  private void validateSingleObjectForScopes(List<ScopeDefinition> scopes, Object result, UserDetails userDetails) {
    if (result instanceof Accessible) {
      Accessible accessible = (Accessible) result;
      accessible.isAccessibleBy(userDetails, scopes);
    } else {
      throw new AccessDeniedException("Resource does not implement Accessible interface");
    }
  }

}
