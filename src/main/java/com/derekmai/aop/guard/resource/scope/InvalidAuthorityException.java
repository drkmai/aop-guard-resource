package com.derekmai.aop.guard.resource.scope;

/**
 * Exception thrown when an authority string cannot be parsed correctly into a {@link ScopeAuthority}.
 *
 * <p>This exception typically indicates that the authority string does not conform to the expected
 * format, which should be {@code ROLE_<SCOPE>_<ROLE>_<RESOURCE_ID>}.</p>
 */
public class InvalidAuthorityException extends Exception {

  /**
   * Constructs a new {@code InvalidAuthorityException} with the specified detail message.
   *
   * @param message the detail message explaining the reason for the exception
   */
  public InvalidAuthorityException(String message) {
    super(message);
  }

  /**
   * Constructs a new {@code InvalidAuthorityException} with the specified detail message and cause.
   *
   * @param message the detail message explaining the reason for the exception
   * @param cause   the underlying cause of the exception
   */
  public InvalidAuthorityException(String message, Throwable cause) {
    super(message, cause);
  }
}
