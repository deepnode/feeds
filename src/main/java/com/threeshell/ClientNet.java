package com.threeshell;

public class ClientNet {

  public int subnet;
  public int mask;
  public String level1;
  public String level2;
  public String prefix;

  public ClientNet ( String strSubnet, String strMask, String level1,
                     String level2, String prefix ) {
    subnet = IPUtils.getNumericIP(strSubnet);
    mask = IPUtils.getNumericIP(strMask);
    this.level1 = level1;
    this.level2 = level2;
    this.prefix = prefix;
  }
}
