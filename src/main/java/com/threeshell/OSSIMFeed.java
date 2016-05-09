package com.threeshell;

import java.io.*;
import java.util.zip.DeflaterOutputStream;
import java.net.Socket;

public class OSSIMFeed {

  private static long nextMsgId = 1;

  public static void main ( String[] args ) {
    if ( args.length < 1 ) {
      System.out.println("usage: OSSIMFeed <console ip>");
      System.out.println("   ... and you pipe in a OSSIM file");
      System.exit(1);
    }

    go(args[0]);
  }

  public static String parseOSSIM ( String line ) {
    String ts = getOssimValue(line, "date");
    if ( ts == null )
      return null;

    String srcIp = getOssimValue(line, "src_ip");
    String dstIp = getOssimValue(line, "dst_ip");
    String data = getOssimValue(line, "data");

    String tag = null;
    String service = "log";
    if ( data != null ) {
      tag = "_i_" + data.replace(',', ';');
      // parse out the service if possible
    }

    StringBuilder sb = new StringBuilder();
    sb.append('o');
    sb.append(String.valueOf(nextMsgId));
    sb.append('\t');
    sb.append(ts);
    sb.append("000\t_|_|");
    sb.append(srcIp);
    sb.append('|');
    sb.append(service);
    sb.append("\t_|_|");
    sb.append(dstIp);
    sb.append('|');
    sb.append(service);
    sb.append("\t1|0.1\t");
    if ( tag != null )
      sb.append(tag);

    nextMsgId++;
    return sb.toString();
  }

  private static String getOssimValue ( String line, String tag ) {
    String searchStr = " " + tag + "='";
    int i = line.indexOf(searchStr);
    if ( i < 0 )
      return null;

    int j = line.indexOf("'", i + searchStr.length());
    if ( j < 0 )
      return null;

    return line.substring(i + searchStr.length(), j);
  }

  public static void go ( String addr ) {
    PrintWriter pw = null;
    BufferedReader sysbr = null;
    try {
      Socket s = new Socket(addr, 4021);
      pw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(s.getOutputStream(), true)));
      pw.println("OSSIM");
      pw.flush();
      System.out.println("outbound connection established");

      sysbr = new BufferedReader(new InputStreamReader(System.in));
      String line;
      int count = 0;
      while ( (line = sysbr.readLine()) != null ) {
        String msg = parseOSSIM(line);
        if ( msg != null )
          pw.println(msg);
        count++;
      }
      System.out.println("sent " + count + " messages to console");
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
    finally {
      try {
        if ( sysbr != null )
          sysbr.close();
        if ( pw != null )
          pw.close();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
  }
}
