package com.derekmai.aop.guard.resource.user;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Strategy interface used to resolve a {@link org.springframework.security.core.userdetails.UserDetails}
 * instance from a given method parameter.
 *
 * <p>
 * This interface is typically used in conjunction with the {@link com.derekmai.aop.guard.resource.scope.ScopeDefinition}
 * annotation to customize how the current user is determined at runtime, particularly when the user information
 * is passed directly as a method parameter or needs to be extracted from a domain-specific object.
 * </p>
 *
 * <p>
 * Custom implementations of this interface should be stateless and thread-safe.
 * </p>
 *
 * <pre>{@code
 * public class CustomUserResolver implements UserDetailsResolver {
 *     public UserDetails resolve(Object param) {
 *         if (param instanceof CustomUser) {
 *             return ((CustomUser) param).toUserDetails();
 *         }
 *         return null;
 *     }
 * }
 * }</pre>
 *
 * @see com.derekmai.aop.guard.resource.scope.ScopeDefinition
 * @see org.springframework.security.core.userdetails.UserDetails
 */
public interface UserDetailsResolver {

  /**
   * Resolves the {@link UserDetails} from a given method parameter.
   *
   * @param param a method parameter passed to the intercepted method
   * @return the resolved {@link UserDetails}, or {@code null} if it cannot be resolved
   */
  UserDetails resolve(Object param);
}