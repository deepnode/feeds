package com.threeshell;

import java.util.HashMap;

public class SpelunkerFieldset {

  public String source;
  public SpelunkerField[] addr1;
  public SpelunkerField[] addr2;
  public SpelunkerField direction;
  public String addr1to2;
  public SpelunkerField measure;
  public String resultFromAddr = null;
  public String resultToAddr = null;
  public String resultMeasure = null;

  public SpelunkerFieldset () {
  }

  public void process ( HashMap<String, String> eventAttrs ) {
    boolean boolAddr1to2 = false;
    String directionVal = direction.getVal(eventAttrs);
    if ( directionVal != null && directionVal.equals(addr1to2) )
      boolAddr1to2 = true;

    resultMeasure = measure.getVal(eventAttrs);
    String strAddr1 = buildAddr(addr1, eventAttrs);
    String strAddr2 = buildAddr(addr2, eventAttrs);
    if (  boolAddr1to2 ) {
      resultFromAddr = strAddr1;
      resultToAddr = strAddr2;
    }
    else {
      resultFromAddr = strAddr2;
      resultToAddr = strAddr1;
    }
  }

  private String buildAddr ( SpelunkerField[] fields, HashMap<String, String> eventAttrs ) {
    StringBuilder sb = new StringBuilder(fields[0].getVal(eventAttrs));
    for ( int i = 1; i < fields.length; i++ ) {
      sb.append('|');
      sb.append(fields[i].getVal(eventAttrs));
    }
    return sb.toString();
  }
}
