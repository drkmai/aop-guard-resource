package com.derekmai.aop.guard.resource.scope;

import com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver;
import com.derekmai.aop.guard.resource.user.UserDetailsResolver;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation used to define the access control scope for a method annotated with {@link com.derekmai.aop.guard.resource.GuardResource}.
 * <p>
 * It allows specifying the scope type, required roles, how to resolve the current user, and optionally the name of
 * the parameter that identifies the user in the method signature.
 * </p>
 *
 * <p>
 * This annotation works in conjunction with AOP-based access control mechanisms handled by
 * {@code GuardResourceAspect} to evaluate whether the currently authenticated user is authorized to
 * access the resource based on their authorities.
 * </p>
 *
 * <pre>{@code
 * @ScopeDefinition(
 *     scopeType = "team",
 *     roles = {"ADMIN", "REVIEWER"},
 *     userResolver = CustomUserResolver.class,
 *     userIdParam = "userId"
 * )
 * }</pre>
 *
 * @see com.derekmai.aop.guard.resource.GuardResource
 * @see com.derekmai.aop.guard.resource.user.UserDetailsResolver
 * @see com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface ScopeDefinition {

  /**
   * The type of scope this resource is protected by (e.g., "project", "team").
   * This corresponds to the prefix in the user's granted authority string.
   *
   * @return the scope type
   */
  String scopeType();

  /**
   * The required roles within the specified scope that grant access.
   * These roles are matched against the current user's authorities.
   *
   * @return an array of accepted roles
   */
  String[] roles();

  /**
   * Resolver class responsible for extracting the {@link org.springframework.security.core.userdetails.UserDetails}
   * from the current context (e.g., SecurityContext).
   * Defaults to {@link com.derekmai.aop.guard.resource.user.DefaultUserDetailsResolver}.
   *
   * @return a class implementing {@link com.derekmai.aop.guard.resource.user.UserDetailsResolver}
   */
  Class<? extends UserDetailsResolver> userResolver() default DefaultUserDetailsResolver.class;

  /**
   * Optional parameter name in the method's signature that contains the user ID (for use with custom resolvers).
   * If not used, user resolution falls back to the resolver logic.
   *
   * @return the parameter name used to locate the user ID
   */
  String userIdParam() default "";
}
