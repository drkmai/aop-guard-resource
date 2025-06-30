package com.derekmai.aop.guard.resource.scope;

public class InvalidAuthorityException extends Exception {

  public InvalidAuthorityException(String message) {
    super(message);
  }

  public InvalidAuthorityException(String message, Throwable cause) {
    super(message, cause);
  }
}
