package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.text.ParseException;

public class Playback {

  private int nextInd = 0;
  private PrintWriter pw;
  private String fname;

  public static void main ( String[] args ) {
    try {
      Playback play = new Playback(args[0]);
      play.go();
    }
    catch ( Exception e ) {
      System.out.println("error: " + e);
      e.printStackTrace(System.out);
    }
  }

  public Playback ( String fname ) {
    this.fname = fname;
  }

  public void go () throws UnknownHostException, IOException, SecurityException,
                           ParseException, InterruptedException {
    Socket s = new Socket("localhost", 4021);
    pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
    pw.println("playback");
    pw.flush();
    pw.println("__cg_ingest");
    pw.flush();

    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line = null;
    while ( (line = br.readLine()) != null ) {
      pw.println(line);
    }

    //pw.println("__cg_normal");
    pw.close();
    s.close();
    br.close();
  }
}


