package org.owasp.url;

import java.util.regex.Pattern;

import com.google.common.base.Optional;

final class PathGlobs {

  private PathGlobs() {
    // Static API
  }

  static Pattern toPattern(Iterable<? extends String> globs) {
    StringBuilder sb = new StringBuilder();
    sb.append("^(?:");
    boolean wroteOne = false;
    for (String glob : globs) {
      if (wroteOne) {
        sb.append('|');
      }
      wroteOne = true;

      // Split the glob so that all "*" and "**" segments appear at the front
      // of tokens and any trailing /? appears by itself.
      int written = 0;
      int n = glob.length();
      for (int i = 0; i <= n; ++i) {
        String sub = null;
        int nMatched = 0;
        if (i == n) {
          sub = "";  // Forces write of last region
          nMatched = 1;
        } else if ("/**/".regionMatches(0, glob, i, 4)) {
          nMatched = 4;
          // /**/ should match /
          sub = "/(?:.*/)?";
        } else if ("/**".regionMatches(0, glob, i, 3) && i + 3 == n) {
          nMatched = 3;
          sub = "/.*\\z";
        } else if ("**".regionMatches(0, glob, i, 2)) {
          nMatched = 2;
          sub = ".*";
        } else if (glob.charAt(i) == '*') {
          nMatched = 1;
          sub = "[^/]*";
        } else if (i + 2 == n && "/?".regionMatches(0, glob, i, 2)) {
          nMatched = 2;
          sub = "/?";
        }
        if (sub != null) {
          if (i != written) {
            String globPart = glob.substring(written, i);
            Optional<String> decodedPart = Percent.decode(globPart);
            if (decodedPart.isPresent()) {
              sb.append(Pattern.quote(decodedPart.get()));
            } else {
              // The caller should check when adding a glob that it
              // decodes properly so this should not occur.
              throw new IllegalArgumentException(globPart);
            }
          }
          sb.append(sub);
          written = i + nMatched;
          i = written - 1;
        }
      }
    }
    if (!wroteOne) {
      // We are joining using | but if there's no operands we
      // should fail to match per the usual semantics of
      // zero-arity OR.
      sb.append("(?!)");
    }
    sb.append(")\\z");
//    System.err.println(Arrays.asList(globs) + " => " + sb);
    return Pattern.compile(sb.toString());
  }

}
