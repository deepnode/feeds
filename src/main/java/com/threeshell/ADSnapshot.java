package com.threeshell;

import java.util.HashMap;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ADSnapshot {

  public static long nextId = 1;
  public String applicationComponentNodeId;
  public long localStartTime;
  public long timeTakenInMilliSecs;
  public String URL;
  public String userExperience;
  public ADHttpParm[] httpParameters;
  public String remoteAddr = null;
  public ADApplication app;

  public ADSnapshot () {
  }

  public String genMessage () {
    StringBuilder sb = new StringBuilder();
    sb.append(String.valueOf(nextId));
    nextId++;
    sb.append('\t');

    sb.append(String.valueOf(localStartTime));
    sb.append('\t');

    sb.append("users");
    sb.append('|');
    for ( ADHttpParm adhp : httpParameters ) {
      if ( adhp.name != null && adhp.name.equals("REMOTE_ADDR") )
        remoteAddr = adhp.value;
    }
    httpParameters = null;

    if ( remoteAddr == null || remoteAddr.length() < 1 )
      sb.append("unknown|unknown|unknown");
    else {
      int i = remoteAddr.indexOf(",");
      if ( i > -1 )
        remoteAddr = remoteAddr.substring(0, i);
      sb.append(AppDynamicsIngest.getLocation(remoteAddr));
      sb.append('|');
      sb.append(remoteAddr);
    }

    sb.append('\t');
    sb.append(app.name);
    sb.append('|');
    if ( URL == null || URL.length() < 1 )
      sb.append("-|-|-");
    else if ( URL.length() == 1 )
      sb.append(URL + "|-|" + URL);
    else {
      String[] urlSplit = URL.substring(1, URL.length()).split("/");
      for ( int i = 0; i < 2; i++ ) {
        if ( urlSplit.length >= i + 1 )
          sb.append(urlSplit[i]);
        else
          sb.append("-");
        sb.append('|');
      }
      sb.append(URL);
    }

    float crit = 0f;
    if ( userExperience == null )
      crit = 0f;
    else if ( userExperience.equals("NORMAL") )
      crit = 0f;
    else if ( userExperience.equals("SLOW") )
      crit = .1f;
    else if ( userExperience.equals("VERY_SLOW") )
      crit = .2f;
    else if ( userExperience.equals("STALL") )
      crit = .3f;
    else if ( userExperience.equals("ERROR") )
      crit = .3f;

    sb.append('\t');
    if ( timeTakenInMilliSecs > 0 )
      sb.append(String.valueOf(timeTakenInMilliSecs));
    else
      sb.append("1");
    sb.append('|');
    sb.append(String.valueOf(crit));

    return sb.toString(); 
  }

  public static String sanitize ( String str ) {
    if ( str == null )
      return "unknown";

    return str.replace('|', '-').replace('\t', '-');
  }
}
