package com.threeshell;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ADNode {

  public String description;
  public int id;
  public String name;
  public int tierId;
  public String tierName;
  public String machineName;

  public String fullPath;

  public ADNode () {
  }
}
