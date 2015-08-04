package com.threeshell;

public class InternalNet {

  public int subnet;
  public int mask;
  public String level1;
  public String level2;

  public InternalNet ( String strSubnet, String strMask, String level1, String level2 ) {
    subnet = IPUtils.getNumericIP(strSubnet);
    mask = IPUtils.getNumericIP(strMask);
    this.level1 = level1;
    this.level2 = level2;
  }
}
