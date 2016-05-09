package com.threeshell;

import java.util.HashMap;

public class SplunkEvent {

  public String resultFromAddr = null;
  public String resultToAddr = null;
  public String resultMeasure = null;
  public String resultTag = null;

  public void process ( HashMap<String, String> eventAttrs ) {
    boolean boolAddr1to2 = false;
    String directionVal = eventAttrs.get("Direction");
    if ( directionVal != null && directionVal.equals("outbound") )
      boolAddr1to2 = true;

    resultMeasure = "1";
    String bytes = eventAttrs.get("TransportHeaderSizeBytes");
    if ( bytes != null ) {
      int j = Integer.parseInt(bytes);
      if ( j > 0 )
        resultMeasure = bytes;
    }

    String prot = eventAttrs.get("Protocol").toLowerCase();
    String strAddr1 = "_|_|" + eventAttrs.get("LocalAddress") + "|" + prot;
    String strAddr2 = "_|_|" + eventAttrs.get("RemoteAddress") + "|" + prot;

    String localPort = eventAttrs.get("LocalPort");
    if ( localPort != null )
      strAddr1 += localPort;

    String remotePort = eventAttrs.get("RemotePort");
    if ( remotePort != null )
      strAddr2 += remotePort;

    String process = eventAttrs.get("ProcessName");
    int i = process.lastIndexOf('\\');
    if ( i >= 0 )
      process = process.substring(i + 1, process.length());
    resultTag = process;

    if (  boolAddr1to2 ) {
      resultFromAddr = strAddr1;
      resultToAddr = strAddr2;
    }
    else {
      resultFromAddr = strAddr2;
      resultToAddr = strAddr1;
    }
  }
}
