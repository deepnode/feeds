package com.threeshell;

import java.io.*;

public class StarlecTest {

  public static void main ( String[] args ) {
    try {
      Starlec starlec = new Starlec();
      FileInputStream fis = new FileInputStream(args[0]);
      int c;
      while ( (c = fis.read()) != -1 )
        starlec.consume(c);
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }
}
