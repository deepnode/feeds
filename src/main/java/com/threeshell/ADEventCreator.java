package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.*;
import java.net.UnknownHostException;
import java.text.*;
import org.apache.commons.codec.binary.Base64;

public class ADEventCreator {

  public static void main ( String[] args ) {
    try {
      for ( int i = 0; i < 100; i++ ) {
        postEvent("test event " + i);
        Thread.sleep(1000);
      }
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  private static void postEvent ( String summary ) throws IOException {
    URL url = new URL("http://localhost:8090/controller/rest/applications/test1/events");
    HttpURLConnection conn = (HttpURLConnection)url.openConnection();
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setDoInput(true);
    //conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    //conn.setRequestProperty("charset", "UTF-8");
    //conn.setRequestProperty("Accept-Charset", "UTF-8");
    String authString = "admin@customer1:appdynamics";
    String authStringEnc = new String(Base64.encodeBase64(authString.getBytes()));
    conn.setRequestProperty("Authorization", "Basic " + authStringEnc);

    OutputStream pw = conn.getOutputStream();
    String parms = "summary=" + URLEncoder.encode(summary) + "&comment=testevent&eventtype=APPLICATION_DEPLOYMENT" +
                   "&severity=ERROR";
    pw.write(parms.getBytes());
    pw.flush();

    String line;
    BufferedReader br;
    try {
      br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
    }
    catch ( IOException ie ) {
      br = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
    }
    while ( (line = br.readLine()) != null )
      System.out.println(line);
    pw.close();
    br.close();
  }
}
