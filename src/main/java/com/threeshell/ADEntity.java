package com.threeshell;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ADEntity {

  public int entityId;
  public String entityType;

  public ADEntity () {
  }
}
