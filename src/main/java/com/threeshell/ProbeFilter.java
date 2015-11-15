package com.threeshell;

import java.util.HashSet;

public class ProbeFilter {

  public String[] srcDstPattern = null;
  public String[] tagSplit = null;
  public boolean focus = false;
  public boolean isFlag = false;
  public boolean isRegex = false;

  public String fromRegex = null;
  public String toRegex = null;
  public String withRegex = null;

  public ProbeFilter ( String line ) throws Exception {
    String fromPattern = null;
    String toPattern = null;
    String tags = null;

    int indOff = 0;
    String[] spl = line.split(" ");
    if ( spl.length > 2 && spl[1].equals("rx") ) {
      isRegex = true;
      indOff = 1;
    }

    if ( spl.length >= 5 + indOff && spl[1 + indOff].equals("from") &&
         spl[3 + indOff].equals("to") ) {
      fromPattern = spl[2 + indOff];
      toPattern = spl[4 + indOff];
    }
    else
      throw new Exception("must include from and to");

    if ( !(spl[0].equals("filter") || spl[0].equals("flag") ||
           spl[0].equals("focus")) )
      throw new Exception("must begin with filter, flag, or focus");

    if ( spl[0].equals("focus") )
      focus = true;
    else if ( spl[0].equals("flag") )
      isFlag = true;

    if ( spl.length > 5 + indOff ) {
      if ( spl[5 + indOff].equals("with") && spl.length > 6 + indOff ) {
        if ( isRegex )
          withRegex = spl[6 + indOff];
        else {
          for ( int i = 6 + indOff; i < spl.length; i++ ) {
            if ( tags == null )
              tags = spl[i];
            else
              tags += ',' + spl[i];
          }
          tagSplit = tags.split(",");
        }
      }
      else
        throw new Exception("have with, but no tags");
    }

    if ( !isRegex ) {
      String raw = fromPattern + '|' + toPattern;
      srcDstPattern = raw.split("\\|");
      if ( srcDstPattern.length != 8 )
        throw new Exception("pattern {" + raw + "} is not length of 8");
    }
    else {
      fromRegex = fromPattern;
      toRegex = toPattern;
    }
  }

  public boolean matches ( String[] target, int startInd ) {
    if ( isRegex ) {
      String str = target[0];
      for ( int i = 1; i < 4; i++ ) {
        if ( i >= target.length )
          break;
        str += '|' + target[i];
      }

      if ( startInd == 0 )
        return str.matches(fromRegex);
      else if ( startInd == 4 )
        return str.matches(toRegex);
      else
        return false;
    }

    for ( int i = 0; i < 4; i++ ) {
      if ( i >= target.length )
        break;
      if ( !srcDstPattern[i + startInd].equals("*") &&
           !srcDstPattern[i + startInd].equals(target[i]) )
        return false;
    }
    return true;
  }

  public boolean tagsMatch ( String[] tagArray, String tag ) {
    if ( isRegex ) {
      if ( tag == null || tag.length() < 1 ) {
        if ( withRegex == null )
          return true;
        return false;
      }

      if ( withRegex == null )
        return true;

      return tag.matches(withRegex);
    }

    if ( tagSplit == null || tagSplit.length < 1 )
      return true;

    if ( tagArray == null || tagArray.length < 1 )
      return false;

    HashSet<String> msgTags = new HashSet<String>();
    for ( String str : tagArray )
      msgTags.add(str);

    for ( String str : tagSplit ) {
      if ( !msgTags.contains(str) )
        return false;
    }
    return true;
  }

  public boolean match ( String[] src, String[] dst, String[] tags, String tag ) {
    boolean match = false;
    if ( ((matches(src, 0) && matches(dst, 4)) ||
          (matches(src, 4) && matches(dst, 0))) &&
         tagsMatch(tags, tag) )
      match = true;

    if ( focus )
      match = !match;

    return match;
  }

  public String getRule () {
    StringBuilder sb = new StringBuilder();
    if ( isFlag )
      sb.append("flag ");
    else if ( focus )
      sb.append("focus ");
    else
      sb.append("filter ");

    if ( isRegex ) {
      sb.append("rx from ");
      sb.append(fromRegex);
      sb.append(" to ");
      sb.append(toRegex);
      if ( withRegex != null ) {
        sb.append(" with ");
        sb.append(withRegex);
      }
    }
    else {
      sb.append("from ");
      sb.append(buildPattern(0, 3));
      sb.append(" to ");
      sb.append(buildPattern(4, 7));

      if ( tagSplit != null && tagSplit.length > 0 ) {
        sb.append(" with ");
        sb.append(tagSplit[0]);
        for ( int i = 1; i < tagSplit.length; i++ ) {
          sb.append(' ');
          sb.append(tagSplit[i]);
        }
      }
    }

    return sb.toString();
  }

  private String buildPattern ( int begin, int end ) {
    StringBuilder sb = new StringBuilder();
    for ( int i = begin; i <= end; i++ ) {
      if ( i > begin )
        sb.append('|');
      sb.append(srcDstPattern[i]);
    }
    return sb.toString();
  }
}
