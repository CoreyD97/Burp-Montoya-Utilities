package com.coreyd97.BurpExtenderUtilities;

public class UnmanagedSettingException extends RuntimeException{
  public UnmanagedSettingException(){}

  public UnmanagedSettingException(String message){ super(message); }

  public UnmanagedSettingException(String message, Throwable cause){
    super(message, cause);
  }

  public UnmanagedSettingException(
    String message, Throwable cause,
    boolean enableSuppression, boolean writableStackTrace
  ){
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public UnmanagedSettingException(Throwable cause){ super(cause); }
}
