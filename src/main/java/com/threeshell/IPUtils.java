package com.threeshell;

public class IPUtils {

  public static int getNumericIP ( String strIP ) {
    int ipInt = 0;
    String[] split = strIP.split("\\.");
    if ( split.length != 4 )
      return 0;

    for ( int i = 0; i < split.length; i++ ) {
      int piece = Integer.parseInt(split[i]);
      if ( piece < 0 || piece > 255 )
        return 0;

      ipInt = (ipInt << 8) + piece;
    }
    return ipInt;
  }

  public static boolean isInSubnet ( int addr, int subnet, int mask ) {
    if ( (addr & mask) == subnet )
      return true;
    return false;
  }
}
