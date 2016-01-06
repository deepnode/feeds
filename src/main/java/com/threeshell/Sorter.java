package com.threeshell;

public class Sorter implements Runnable {

  private MsgSource[] sources;
  private Pro2be probe;

  public Sorter ( MsgSource[] sources, Pro2be probe ) {
    this.sources = sources;
    this.probe = probe;
  }

  public void run () {
    try {
      boolean couldBeMore = true;
      while ( couldBeMore ) {
        couldBeMore = false;
        long earliestTime = 0;
        MsgSource earliestSource = null;
        for ( MsgSource source : sources ) {
          if ( source.hasMore() ) {
            couldBeMore = true;
            if ( earliestTime == 0 || source.getCurTime() < earliestTime ) {
              earliestTime = source.getCurTime();
              earliestSource = source;
            }
          }
        }

        if ( earliestSource != null )
          probe.sendMessage(earliestSource.getCurMsg());
      }
    }
    catch ( Exception e ) {
      System.out.println("error sorting msg sources: " + e);
      e.printStackTrace(System.out);
    }
  }
}
