package com.derekmai.aop.guard.resource;

import com.derekmai.aop.guard.resource.scope.ScopeDefinition;
import com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark a method as protected by one or more access control scopes.
 *
 * <p>
 * This annotation is intended to be used on methods that require authorization checks
 * based on defined scopes. Each scope is represented by a {@link ScopeDefinition},
 * specifying the scope type, required roles, user resolver, and other parameters.
 * </p>
 *
 * <p>
 * When applied, the method execution is intercepted (e.g., via AOP), and access
 * is granted only if the current user meets the authorization criteria for
 * at least one of the specified scopes.
 * </p>
 *
 * <p>
 *     Example of a GuardResource for validating roles from the Authentication Principal (By using {@link DefaultUserDetailsResolver})
 *     and also validating access for the userId in the method params being guarded with MyCustomUserResolver as User Resolver.
 * </p>
 * <pre>{@code
 * @GuardResource(
 *   scopes = {
 *     @ScopeDefinition(scopeType = "project", roles = {"ADMIN", "MANAGER"}),
 *     @ScopeDefinition(scopeType = "project", roles = {"MANAGER"}, userIdParam = "userId", userResolver = MyCustomUserResolver.class)
 *   }
 * )
 * }</pre>
 *
 * @see ScopeDefinition
 * @see GuardResourceAspect
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface GuardResource {

  /**
   * An array of {@link ScopeDefinition} annotations representing
   * the different scopes and roles required to access the annotated method.
   *
   * @return array of scope definitions
   */
  ScopeDefinition[] scopes();
}
