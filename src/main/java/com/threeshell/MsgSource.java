package com.threeshell;

public interface MsgSource {

  public boolean hasMore ();

  public long getCurTime ();

  public String getCurMsg ();
}
