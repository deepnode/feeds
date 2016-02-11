package com.threeshell;

import java.io.*;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.zip.GZIPInputStream;
import java.util.concurrent.LinkedBlockingQueue;

public class LoadSender implements Runnable {

  private Socket s;
  private PrintWriter fspw;
  private long startDate;
  private long endDate;
  private BufferedReader curFileBr = null;
  private Pro2be theProbe;
  private String[] subdirList = null;
  private int curSubdirInd = 0;
  private String[] fileList = null;
  private int curFileInd = 0;
  private String storeRecord = null;
  private String mainPath = null;
  private boolean sendLive = false;
  public LinkedBlockingQueue<String> queue;
  private String curFileName;
  public String maxFileName = null;
  public boolean isDead = false;

  public LoadSender ( Socket s, PrintWriter pw, Pro2be thePro2be ) {
    this.s = s;
    this.fspw = pw;
    this.theProbe = thePro2be;
  }

  public void run () {
    try {
      System.out.println("load connection from " + s.getInetAddress());
      monitor();
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  private void monitor () throws IOException, InterruptedException, ParseException {
    BufferedReader fsbr = new BufferedReader(new InputStreamReader(s.getInputStream()));
    System.out.println("waiting for first line...");
    String commandStr = fsbr.readLine();
    String[] split = commandStr.split("\t");
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    System.out.println("LoadSender start " + split[1]);
    if ( split[1].equals("now") ) {
      sendLive = true;
      subscribe(true);
    }
    else {
      startDate = sdf.parse(split[1]).getTime();
      if ( split[2].equals("now") && !split[1].equals("now") ) {
        endDate = -1;
        subscribe(false);
      }
      else
        endDate = sdf.parse(split[2]).getTime();
      if ( !findStart() ) {
        System.out.println("starting file not found, going live");
        sendLive = true;
        subscribe(true);
      }
    }

    boolean isGood = true;
    try {
      long lastMsgTime = System.currentTimeMillis();
      fspw.println("ping");
      fspw.flush();
      //System.out.println("sent first ping...");
      while ( fspw != null && isGood ) {
        String str = getNextMsg();
        if ( str != null ) {
          if ( str.equals("__continue") ) {
            if ( lastMsgTime + 100l < System.currentTimeMillis() ) {
              lastMsgTime = System.currentTimeMillis();
              //System.out.println("sending ping");
              fspw.println("ping");
              fspw.flush();
            }
            else {
              try {
                //System.out.println("sleeping...");
                Thread.sleep(20);
              }
              catch ( Exception e ) {
                System.out.println("error sleeping in getNextMsg live: " + e);
              }
            }
          }
          else {
            lastMsgTime = System.currentTimeMillis();
            //System.out.println(str);
            fspw.println(str);
            fspw.flush();
          }
        }
        else {
          System.out.println("str is null!!!");
          if ( curFileBr != null )
            curFileBr.close();
          isGood = false;
        }
      }
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
    finally {
      isDead = true;
      System.out.println("closing connection to " + s.getInetAddress());
      fsbr.close();
      fspw.close();
      s.close();
    }
  }

  private void subscribe ( boolean justSendLive ) {
    queue = new LinkedBlockingQueue<String>();
    theProbe.collector.subscribe(this, justSendLive);
  }

  private String getNextMsg () throws IOException, ParseException, InterruptedException {
    if ( storeRecord != null ) {
      String temp = storeRecord;
      storeRecord = null;
      return temp;
    }

    if ( sendLive ) {
      String str = queue.poll();
      if ( str == null ) {
        //System.out.println("ls queue size " + queue.size());
        return "__continue";
      }
      return str;
    }
      
    String nextLine = null;
    try {
      nextLine = curFileBr.readLine();
    }
    catch ( Exception e ) {
      System.out.println("error reading next line: " + e);
    }

    if ( nextLine == null ) {
      if ( checkMaxFileName() || !openNextFile() ) {
        if ( endDate == -1 ) {
          sendLive = true;
          return "__continue";
        }
        return null;
      }
      return "__continue";
    }
    else {
      String[] split = nextLine.split("\t");
      long ts = Long.parseLong(split[1]);
      if ( endDate != -1 && ts > endDate )
        return null;
      return nextLine;
    }
  }

  private boolean checkMaxFileName () {
    if ( maxFileName == null )
      return false;

    if ( maxFileName.equals(curFileName) )
      return true;
    return false;
  }

  private boolean openNextFile () throws IOException {
    curFileBr.close();
    boolean gotFile = false;
    boolean moreFiles = true;
    while ( moreFiles && !gotFile ) {
      curFileInd++;
      if ( curFileInd >= fileList.length ) {
        curFileInd = 0;
        curSubdirInd++;
        if ( curSubdirInd >= subdirList.length ) {
          moreFiles = false;
          continue;
        }

        File subDir = new File(mainPath + subdirList[curSubdirInd]);
        fileList = subDir.list();
        if ( fileList == null || fileList.length <= 1 )
          continue;
      }

      try {
        curFileName = makeFileName();
        if ( curFileName.endsWith("_pend.gz") )
          continue;

        curFileBr = new BufferedReader(new InputStreamReader(new GZIPInputStream(
                      new FileInputStream(curFileName))));
        System.out.println("loading from " + curFileName);
        gotFile = true;
      }
      catch ( Exception e ) {
        System.out.println("error opening {" + curFileName + "}: " + e);
      }
    }

    if ( !gotFile )
      return false;
    return true;
  }

  private boolean findStart () throws IOException, ParseException {
    mainPath = theProbe.storagePath;
    if ( !mainPath.endsWith(File.separator) )
      mainPath += File.separator;

    File mainDir = new File(mainPath);
    subdirList = mainDir.list();
    while ( curSubdirInd < subdirList.length - 1 &&
            Long.parseLong(subdirList[curSubdirInd]) <= startDate )
      curSubdirInd++;

    File subDir = new File(mainPath + subdirList[curSubdirInd]);
    fileList = subDir.list();

    while ( curFileInd < fileList.length ) {
      if ( fileList[curFileInd].endsWith("_pend.gz") )
        return false;

      if ( Long.parseLong(fileList[curFileInd].substring(0, fileList[curFileInd].length() - 3))
            > startDate ) {
        curFileInd--;
        if ( curFileInd < 0 )
          return false;
        else
          break;
      }

      curFileInd++;
    }

    if ( curFileInd > fileList.length )
      return false;

    curFileBr = new BufferedReader(new InputStreamReader(new GZIPInputStream(
                  new FileInputStream(makeFileName()))));
    while ( (storeRecord = curFileBr.readLine()) != null ) {
      String[] split = storeRecord.split("\t");
      long curTs = Long.parseLong(split[1]);
      if ( curTs >= startDate )
        break;
    }
    return true;
  }

  private String makeFileName () {
    return mainPath + subdirList[curSubdirInd] + File.separator + fileList[curFileInd];
  }
}
