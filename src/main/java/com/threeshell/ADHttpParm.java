package com.threeshell;

import java.util.HashMap;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ADHttpParm {

  public String name;
  public String value;

  public ADHttpParm () {
  }
}
