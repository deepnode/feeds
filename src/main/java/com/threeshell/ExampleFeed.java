package com.threeshell;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.zip.DeflaterOutputStream;

public class ExampleFeed {

  private PrintWriter pw;
  private BufferedReader br;
  private long nextId = 1;

  public static void main ( String[] args ) {
    try {
      ExampleFeed feed = new ExampleFeed();
      feed.run();
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  public void run () {
    while ( true ) {
      Socket s = null;
      try {
        s = new Socket("localhost", 4021);
        pw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(s.getOutputStream(), true)));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("example_feed");
        pw.flush();
        monitor();
      }
      catch ( Exception e ) {
        try {
          pw.close();
        }
        catch ( Exception e2 ) {
        }
        try {
          br.close();
        }
        catch ( Exception e2 ) {
        }
        try {
          if ( s != null )
            s.close();
        }
        catch ( Exception e3 ) {
        }
        System.out.println("error: " + e);
	try {
          Thread.sleep(8000);
	}
	catch ( InterruptedException ie ) {}
      }
    }
  }

  private void monitor () throws IOException, InterruptedException {
    boolean isGood = true;
    long lastPing = 0;
    boolean toggle = false;

    pw.println("__td_tag1|sphere|1.0|.3|0.0|pulse");
    pw.println("__td_tag2|torus|0.0|.4|.9|spin");
    pw.println("__td_tag3|cube|1.0|.2|.2|pulse,spin");
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();
      }

      int bobSess = (int)Math.floor(Math.random() * 10d);
      int aliceSess = (int)Math.floor(Math.random() * 17d);
      int size = 100 + (int)Math.floor(Math.random() * 1000d);
      float level = (float)(Math.random());
      toggle = !toggle;

      String tag = "";
      if ( Math.random() < .1d )
        tag = "tag1";
      if ( Math.random() > .94d )
        tag = "tag2";
      double rd = Math.random();
      if ( rd > .5d && rd < .52d )
        tag = "tag3";

      String idAndTs = String.valueOf(nextId) + '\t' + String.valueOf(System.currentTimeMillis()) + '\t';
      nextId++;
      if ( toggle )
        pw.println(idAndTs + "mars|olympus|bob|session" + bobSess + "\tvenus|newdc|alice|session" +
		   aliceSess + "\t" + size + "|" + level + "\t" + tag);
      else
        pw.println(idAndTs + "venus|newdc|alice|session" + aliceSess + "\tmars|olympus|bob|session" +
                   bobSess + "\t" + size + "|" + level + "\t" + tag);
      Thread.sleep(100);
    }
  }
}
