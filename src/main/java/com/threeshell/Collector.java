package com.threeshell;

import java.io.*;
import java.util.zip.GZIPOutputStream;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.LinkedList;
import java.util.HashSet;

public class Collector implements Runnable {

  private Pro2be theProbe;
  private PrintWriter curFilePw = null;
  private int bytesWritten = 0;
  private String idPrefix = "";
  public static long MAX_RAWBYTES_PER_FILE = 10000000;
  public static int MAX_FILES_PER_DIR = 100;
  private String curRename = null;
  private LinkedBlockingQueue<LoadSender> senderQueue = new LinkedBlockingQueue<LoadSender>();
  private HashSet<LoadSender> senders = new HashSet<LoadSender>();
  private LinkedBlockingQueue<String> fileOutQueue = new LinkedBlockingQueue<String>();
  private String prevFileName = null;
  private FileMsgWriter fmw = null;
  private Thread fmwt = null;
  private boolean die = false;

  public Collector ( Pro2be thePro2be ) {
    this.theProbe = thePro2be;
  }

  public void run () {
    Runtime.getRuntime().addShutdownHook(new Thread(new CollectorShutdown()));
    fmw = new FileMsgWriter();
    fmwt = new Thread(fmw);
    fmwt.start();

    while ( true ) {
      try {
        String str = theProbe.outQueue.poll(100, TimeUnit.MILLISECONDS);
        if ( str != null ) {
          if ( str.startsWith("__") )
            continue;
          fileOutQueue.offer(str);
          writeMsgLive(str);
        }
      }
      catch ( Exception e ) {
        System.out.println("collector error processing: " + e);
        e.printStackTrace(System.out);
      }
    }
  }
  
  private void writeMsgLive ( String str ) {
    if ( senderQueue.size() > 0 ) {
      LoadSender ls;
      try {
        while ( (ls = senderQueue.poll()) != null ) {
          System.out.println("adding sender");
          senders.add(ls);
        }
      }
      catch ( Exception e ) {
        System.out.println("error processing pending senders: " + e);
      }
    }

    //pendingMessages.offer(str);
    LinkedList<LoadSender> removals = null;
    for ( LoadSender ls : senders ) {
      if ( ls.isDead ) {
        if ( removals == null )
          removals = new LinkedList<LoadSender>();
        removals.add(ls);
      }
      else {
        ls.queue.offer(str);
        //if ( ls.queue.size() % 100 == 0 )
        //  System.out.println("sender queue now has " + ls.queue.size());
      }
    }

    if ( removals != null ) {
      for ( LoadSender ls : removals ) {
        System.out.println("removing dead LoadSender");
        senders.remove(ls);
      }
    }
  }

  private void writeMsgFile ( String str ) throws IOException {
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
      closeAndRename();

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

    curRename = subPath + File.separator + strTimestamp;
    System.out.println("opening file " + curRename + "_pend.gz");
    curFilePw = new PrintWriter(
                 new OutputStreamWriter(
                  new GZIPOutputStream(
                   new FileOutputStream(curRename + "_pend.gz"))));
  }

  public static void createIfNotExist ( String dirName ) throws IOException {
    File dir = new File(dirName);
    if ( !dir.exists() ) {
      System.out.println("creating directory " + dirName);
      dir.mkdir();
    }
  }

  private void closeAndRename () throws IOException {
    curFilePw.close();
    prevFileName = curRename + ".gz";
    File f = new File(curRename + "_pend.gz");
    f.renameTo(new File(curRename + ".gz"));
    //synchronized ( pendSync ) {
    //  pendingMessages = new LinkedList<String>();
    //}
  }

  public void subscribe ( LoadSender ls, boolean justNow ) {
    ls.maxFileName = prevFileName;
    if ( !justNow ) {
      //for ( String str : pendingMessages )
      //  ls.queue.offer(str);
    }
    senderQueue.offer(ls);
  }

  class FileMsgWriter implements Runnable {

    public void run () {
      try {
        while ( !die ) {
          String str = fileOutQueue.poll(100, TimeUnit.MILLISECONDS);
          if ( str != null )
            writeMsgFile(str);
        }
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
  }

  class CollectorShutdown implements Runnable {

    public void run () {
      try {
        die = true;
        fmwt.join();

        if ( curFilePw != null ) {
          System.out.println("shutdown hook closing collector file");
          closeAndRename();
        }
      }
      catch ( Exception e ) {
        System.out.println("error in Collector Shutdown hook: " + e);
        e.printStackTrace(System.out);
      }
    }
  }
}
