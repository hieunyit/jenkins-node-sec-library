package org.jenkinsci.nodesec

import java.io.File

class ShellUtils {
  static String shellQuote(String value) {
    if (!value) {
      return "''"
    }
    String escaped = value.replace("'", "'\"'\"'")
    return "'${escaped}'"
  }

  static String parentDir(String path) {
    if (!path) {
      return ''
    }
    String parent = new File(path).parent
    return parent ?: ''
  }
}
