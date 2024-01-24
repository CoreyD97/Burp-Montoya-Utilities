package com.coreyd97.BurpExtenderUtilities.nameManager;

public class NameCollisionException extends RuntimeException{
  public NameCollisionException()              {}

  public NameCollisionException(String message){ super(message); }

  public NameCollisionException(String message, Throwable cause){
    super(message, cause);
  }

  public NameCollisionException(
    String message, Throwable cause,
    boolean enableSuppression, boolean writableStackTrace
  ){
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public NameCollisionException(Throwable cause){ super(cause); }
}
