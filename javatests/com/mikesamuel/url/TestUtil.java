package com.mikesamuel.url;

import com.mikesamuel.url.Diagnostic.Receiver;

final class TestUtil {

  /** Logs messages found during test failure to stderr. */
  static final Receiver<URLValue> STDERR_RECEIVER = new Receiver<URLValue>() {

    @Override
    public void note(Diagnostic d, URLValue context) {
      Class<? extends Diagnostic> dc = d.getClass();
      String cn = d.getClass().getSimpleName();
      if ("Diagnostics".equals(cn) && dc.isMemberClass()) {
        cn = dc.getEnclosingClass().getSimpleName();
      }
      System.err.println(cn + "." + d + ": " + context);
    }

  };

}
