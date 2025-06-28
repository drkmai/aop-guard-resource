package com.derekmai.aop.guard.resource.user;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Objects;
/**
 * Default implementation of {@link UserDetailsResolver} that extracts the current
 * {@link org.springframework.security.core.userdetails.UserDetails} from a given {@link org.springframework.security.core.Authentication} object.
 *
 * <p>
 * This resolver expects an instance of {@code Authentication} as input and validates that it contains
 * a valid {@code UserDetails} principal. If the input is invalid or does not meet expectations,
 * it throws an {@link org.springframework.security.access.AccessDeniedException}.
 * </p>
 *
 * <p>
 * This implementation is used as the default resolver in conjunction with the
 * {@link com.derekmai.aop.guard.resource.scope.ScopeDefinition} annotation, unless a custom resolver is explicitly provided.
 * </p>
 *
 * <pre>{@code
 * @ScopeDefinition(
 *     scopeType = "team",
 *     roles = {"ADMIN"},
 *     userResolver = DefaultUserDetailsResolver.class
 * )
 * }</pre>
 *
 * @see UserDetailsResolver
 * @see org.springframework.security.core.userdetails.UserDetails
 * @see org.springframework.security.core.Authentication
 * @see com.derekmai.aop.guard.resource.scope.ScopeDefinition
 *
 * @see UserDetailsResolver
 * @see org.springframework.security.core.Authentication
 * @see org.springframework.security.core.userdetails.UserDetails
 * @see org.springframework.security.access.AccessDeniedException
 */
@Component
public class DefaultUserDetailsResolver implements UserDetailsResolver {

  /**
   * Resolves {@link UserDetails} from the provided {@link Authentication} object.
   *
   * @param param the object expected to be an {@link Authentication} instance
   * @return the extracted {@link UserDetails}
   * @throws org.springframework.security.access.AccessDeniedException
   *         if the input is invalid or the user is not authenticated
   */
  @Override
  public UserDetails resolve(Object param) {
    if (Objects.isNull(param) || !(param instanceof Authentication)) {
      throw new AccessDeniedException("Object provided is not an instance of Authentication");
    }

    Authentication authentication = (Authentication) param;
    if (Objects.isNull(authentication.getPrincipal())) {
      throw new AccessDeniedException("User not authenticated");
    }

    if (!(authentication.getPrincipal() instanceof UserDetails)) {
      throw new AccessDeniedException("Invalid user principal type");
    }

    return (UserDetails) authentication.getPrincipal();
  }
}
