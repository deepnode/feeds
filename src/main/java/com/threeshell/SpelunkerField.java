package com.threeshell;

import java.util.HashMap;
import java.io.File;

public class SpelunkerField {

  public String type;
  public String value;
  
  public SpelunkerField () {
  }

  public String getVal ( HashMap<String, String> eventAttrs ) {
    if ( type.equals("literal") )
      return value;

    String val = eventAttrs.get(value);
    if ( type.equalsIgnoreCase("eventattr") )
      return val;
    else if ( type.equals("getFilePart") )
      return getFilePart(val);
    else if ( type.equals("getPortTrunc") )
      return getPortTrunc(val);
    else if ( type.equals("getLocation") )
      return SplunkIngest.splunkIngest.getLocation(val);
    else
      return null;
  }

  public static String getFilePart ( String val ) {
    int sepInd = val.lastIndexOf(File.separator);
    if ( sepInd > -1 )
      return val.substring(sepInd + 1, val.length());
    return val;
  }

  public static String getPortTrunc ( String val ) {
    if ( Integer.parseInt(val) > 1024 )
      return ">1024";
    return val;
  }
}
