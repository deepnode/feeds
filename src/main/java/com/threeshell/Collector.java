package com.threeshell;

import java.io.*;
import java.util.zip.GZIPOutputStream;
import java.util.concurrent.TimeUnit;

public class Collector implements Runnable {

  private Pro2be theProbe;
  private PrintWriter curFilePw = null;
  private int bytesWritten = 0;
  private String idPrefix = "";
  public static long MAX_RAWBYTES_PER_FILE = 10000000;
  public static int MAX_FILES_PER_DIR = 100;

  public Collector ( Pro2be thePro2be ) {
    this.theProbe = thePro2be;
  }

  public void run () {
    Runtime.getRuntime().addShutdownHook(new Thread(new CollectorShutdown()));
    while ( true ) {
      try {
        String str = theProbe.outQueue.poll(100, TimeUnit.MILLISECONDS);
        if ( str != null )
          writeMsg(str);
        else {
          try {
            Thread.sleep(100);
          }
          catch ( InterruptedException ie ) {
            System.out.println("error in collector sleep: " + ie);
          }
        }
      }
      catch ( Exception e ) {
        System.out.println("collector error processing: " + e);
        e.printStackTrace(System.out);
      }
    }
  }
  
  private void writeMsg ( String str ) throws IOException {
    if ( str.startsWith("__") )
      return;

    String[] split = str.split("\t");
    if ( split.length < 5 )
      return;

    if ( curFilePw == null )
      openNextFile(split[1]);
    else if ( bytesWritten > MAX_RAWBYTES_PER_FILE ) {
      openNextFile(split[1]);
      bytesWritten = 0;
    }

    curFilePw.print(idPrefix);
    curFilePw.println(str);
    bytesWritten += idPrefix.length() + str.length() + 1;
    // here we would fetch the packet and save to the packet store
    // fetch using the original id, store using the prefix + the id
  }

  private void openNextFile ( String strTimestamp ) throws IOException {
    if ( curFilePw != null )
      curFilePw.close();

    String mainPath = theProbe.storagePath;
    if ( !mainPath.endsWith(File.separator) )
      mainPath += File.separator;

    File mainDir = new File(mainPath);
    String[] subdirList = mainDir.list();

    String subPath = mainPath + strTimestamp;
    if ( subdirList != null && subdirList.length > 0 ) {
      String subPathTemp = mainPath + subdirList[subdirList.length - 1];
      File subDir = new File(subPathTemp);
      String[] fileList = subDir.list();
      if ( fileList.length < MAX_FILES_PER_DIR )
        subPath = subPathTemp;
    }

    createIfNotExist(subPath);

    curFilePw = new PrintWriter(
                 new OutputStreamWriter(
                  new GZIPOutputStream(
                   new FileOutputStream(subPath + File.separator +
                                        strTimestamp + ".gz"))));
  }

  public static void createIfNotExist ( String dirName ) throws IOException {
    File dir = new File(dirName);
    if ( !dir.exists() ) {
      System.out.println("creating directory " + dirName);
      dir.mkdir();
    }
  }

  class CollectorShutdown implements Runnable {

    public void run () {
      try {
        if ( curFilePw != null ) {
          System.out.println("shutdown hook closing collector file");
          curFilePw.close();
        }
      }
      catch ( Exception e ) {
        System.out.println("error in Collector Shutdown hook: " + e);
        e.printStackTrace(System.out);
      }
    }
  }
}
