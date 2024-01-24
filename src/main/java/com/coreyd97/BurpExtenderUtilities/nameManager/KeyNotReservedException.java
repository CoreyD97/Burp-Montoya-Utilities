package com.coreyd97.BurpExtenderUtilities.nameManager;

public class KeyNotReservedException extends RuntimeException{
  public KeyNotReservedException(){}

  public KeyNotReservedException(String message){ super(message); }

  public KeyNotReservedException(String message, Throwable cause){
    super(message, cause);
  }

  public KeyNotReservedException(
    String message, Throwable cause,
    boolean enableSuppression, boolean writableStackTrace
  ){
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public KeyNotReservedException(Throwable cause){ super(cause); }
}
