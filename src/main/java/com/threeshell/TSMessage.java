package com.threeshell;

public class TSMessage {

  public static final String BO_PREFIX = "__bo_";
  public static final String TD_PREFIX = "__td_";
  public static final int OUTPUT_TYPE_BASH = 1;
  public static final int OUTPUT_TYPE_NOPARSE = 2;

  public String[][] categories = null;
  public String extra = null;
  public String tag = null;
  public long measure;
  public float priority;
  public String raw;
  public long incept;
  public boolean isBashOutput = false;
  public boolean isTagDef = false;
  public boolean modified = false;

  public TSMessage ( String raw ) {
    if ( raw.startsWith(BO_PREFIX) ) {
      this.raw = raw.substring(BO_PREFIX.length(), raw.length());
      isBashOutput = true;
      return;
    }
    if ( raw.startsWith(TD_PREFIX) ) {
      this.raw = raw.substring(TD_PREFIX.length(), raw.length());
      isTagDef = true;
      return;
    }

    this.raw = raw;
    //incept = System.currentTimeMillis();

    String[] split = raw.split("\t");
    if ( split.length < 3 )
      return;

    incept = Long.parseLong(split[0]);

    categories = new String[2][];
    for ( int i = 0; i < 2; i++ ) {
      if ( split[i + 1] == null || split[i + 1].length() < 1 )
        categories[i] = null;
      else
        categories[i] = split[i + 1].split("\\|");
    }

    if ( split.length < 4 )
      return;

    String[] measSplit = split[3].split("\\|");
    measure = Long.parseLong(measSplit[0]);
    priority = Float.parseFloat(measSplit[1]);
    if ( priority > 1f )
      priority = 1f;
    else if ( priority < 0f )
      priority = 0f;

    if ( split.length >= 5 && split[4] != null && split[4].length() > 0 )
      tag = split[4];
    if ( split.length >= 6 )
      extra = split[5];
  }

  public TSMessage ( int outputType, String raw ) {
    if ( outputType == OUTPUT_TYPE_BASH ) {
      this.raw = BO_PREFIX + raw;
      this.isBashOutput = true;
    }
    else if ( outputType == OUTPUT_TYPE_NOPARSE )
      this.raw = raw;
  }

  public String getCatKey ( int catIndex, int lastKeyIndex ) {
    StringBuffer sb = new StringBuffer();
    for ( int i = 0; i <= lastKeyIndex; i++ ) {
      sb.append(categories[catIndex][i]);
      if ( i < lastKeyIndex )
        sb.append('|');
    }
    return sb.toString();
  }

  public String reconstruct () {
    if ( isBashOutput || !modified )
      return raw;

    StringBuffer sb = new StringBuffer();
    sb.append(String.valueOf(incept) + '\t');
    for ( int i = 0; i < categories.length; i++ ) {
      if ( categories[i] != null ) {
        for ( int j = 0; j < categories[i].length; j++ ) {
          if ( j > 0 )
            sb.append('|');
          sb.append(categories[i][j]);
        }
      }
      sb.append('\t');
    }

    sb.append(String.valueOf(measure));
    sb.append('|');
    sb.append(String.valueOf(priority));
    return sb.toString();
  }
}
