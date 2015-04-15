package com.threeshell;

import java.util.HashMap;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ADEvent {

  public ADEntity[] affectedEntities;
  public long eventTime;
  public long id;
  public String severity;
  public String summary;

  public ADEvent () {
  }

  public String genMessage ( ADApplication app, HashMap<String, ADNode> nodeMap ) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.valueOf(id));
    sb.append('\t');

    sb.append(String.valueOf(eventTime));
    sb.append('\t');

    sb.append("summaries|");
    sb.append(sanitize(app.name));
    sb.append('|');
    sb.append(sanitize(severity));
    sb.append('|');
    sb.append(sanitize(summary));
    sb.append('\t');

    sb.append(sanitize(app.name));
    sb.append('|');

    ADNode node = null;
    for ( ADEntity entity : affectedEntities ) {
      if ( entity.entityType.equals("APPLICATION_COMPONENT_NODE") )
        node = nodeMap.get(String.valueOf(entity.entityId));
    }

    if ( node != null ) {
      sb.append(sanitize(node.tierName));
      sb.append('|');
      sb.append(sanitize(node.machineName));
      sb.append('|');
      sb.append(sanitize(node.name));
    }
    else {
      sb.append("unknown");
      sb.append('|');
      sb.append("unknown");
      sb.append('|');
      sb.append("unknown");
    }

    float crit = 0f;
    if ( severity != null && severity.equals("WARN") )
      crit = .5f;
    else if ( severity != null && severity.equals("ERROR") )
      crit = 1.0f;

    sb.append('\t');
    sb.append("10");
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
