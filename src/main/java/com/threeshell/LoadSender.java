package com.threeshell;

import java.io.*;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.zip.GZIPInputStream;

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
    System.out.println("LoadSender start " + split[1] + ", end " + split[2]);
    startDate = sdf.parse(split[1]).getTime();
    endDate = sdf.parse(split[2]).getTime();
    findStart();

    boolean isGood = true;
    while ( fspw != null && isGood ) {
      String str = getNextMsg();
      if ( str != null ) {
        if ( str.equals("__continue") )
          continue;
        fspw.println(str);
      }
      else {
        if ( curFileBr != null )
          curFileBr.close();
        isGood = false;
      }
    }
    System.out.println("closing connection to " + s.getInetAddress());
    fsbr.close();
    fspw.close();
    s.close();
  }

  private String getNextMsg () throws IOException, ParseException {
    if ( storeRecord != null ) {
      String temp = storeRecord;
      storeRecord = null;
      return temp;
    }

    String nextLine = null;
    try {
      nextLine = curFileBr.readLine();
    }
    catch ( Exception e ) {
      System.out.println("error reading next line: " + e);
    }

    if ( nextLine == null ) {
      if ( !openNextFile() )
        return null;
      return "__continue";
    }
    else {
      String[] split = nextLine.split("\t");
      long ts = Long.parseLong(split[1]);
      if ( ts > endDate )
        return null;
      return nextLine;
    }
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
        curFileBr = new BufferedReader(new InputStreamReader(new GZIPInputStream(
                      new FileInputStream(makeFileName()))));
        System.out.println("loading from " + makeFileName());
        gotFile = true;
      }
      catch ( Exception e ) {
        System.out.println("error opening {" + makeFileName() + "}: " + e);
      }
    }

    if ( !gotFile )
      return false;
    return true;
  }

  private void findStart () throws IOException, ParseException {
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

    while ( curFileInd < fileList.length - 1 &&
            Long.parseLong(fileList[curFileInd].substring(0, fileList[curFileInd].length() - 3))
            <= startDate )
      curFileInd++;

    curFileBr = new BufferedReader(new InputStreamReader(new GZIPInputStream(
                  new FileInputStream(makeFileName()))));
    while ( (storeRecord = curFileBr.readLine()) != null ) {
      String[] split = storeRecord.split("\t");
      long curTs = Long.parseLong(split[1]);
      if ( curTs >= startDate )
        break;
    }
  }

  private String makeFileName () {
    return mainPath + subdirList[curSubdirInd] + File.separator + fileList[curFileInd];
  }
}
