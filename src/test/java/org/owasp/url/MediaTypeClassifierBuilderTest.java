package org.owasp.url;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.google.common.net.MediaType;

@SuppressWarnings({ "javadoc", "static-method" })
public final class MediaTypeClassifierBuilderTest {

  private static void runClassifierTests(
      MediaTypeClassifier p,
      UrlContext context,
      String[] shouldMatch,
      String[] shouldNotMatch,
      String[] invalids) {

    Diagnostic.CollectingReceiver<UrlValue> cr = Diagnostic.CollectingReceiver.from(
        TestUtil.STDERR_RECEIVER);

    try {
      for (int i = 0; i < shouldMatch.length; ++i) {
        cr.clear();
        String url = shouldMatch[i];
        UrlValue inp = UrlValue.from(context, url);
        assertEquals(
            i + ": " + url,

            Classification.MATCH,

            p.apply(inp, cr));
      }

      for (int i = 0; i < shouldNotMatch.length; ++i) {
        cr.clear();
        String url = shouldNotMatch[i];
        UrlValue inp = UrlValue.from(context, url);
        assertEquals(
            i + ": " + url,
            Classification.NOT_A_MATCH,
            p.apply(inp, cr));
      }

      for (int i = 0; i < invalids.length; ++i) {
        cr.clear();
        String url = invalids[i];
        UrlValue inp = UrlValue.from(context, url);
        assertEquals(
            i + ": " + url,
            Classification.INVALID,
            p.apply(inp, cr));
      }

      cr.clear();
    } finally {
      cr.flush();
    }
  }

  @Test
  public void testNoWildcard() {
    runClassifierTests(
        MediaTypeClassifiers.builder()
        .type("text", "plain")
        .build(),

        UrlContext.DEFAULT,

        new String[] {
            "data:text/plain,",
            "data:tExt/Plain,",
            "data:text/plain;charset=UTF-8,",
            "data:text/plain;charset=\"UTF-8\",",
            "data:text/plain;charset=ascii,",
            "data:text/plain;foo=bar,",
        },
        new String[] {
            "data:text/html,",
            "data:image/png,",
            "data:application/javascript,",
        },
        new String[] {
            "data:*/plain,",
            "data:%2a/plain,",
            "data:*/*,",
            "data:text/*,",
            "data:%2a/%2a,",
            "data:*/*,",
            "data:%2a/%2a,",
        });
  }

  @Test
  public void testSubtypeWildcard() {
    runClassifierTests(
        MediaTypeClassifiers.builder()
        .type("text", "*")
        .build(),

        UrlContext.DEFAULT,

        new String[] {
            "data:text/plain,",
            "data:tExt/Plain,",
            "data:text/plain;charset=UTF-8,",
            "data:text/plain;charset=\"UTF-8\",",
            "data:text/plain;charset=ascii,",
            "data:text/plain;foo=bar,",
            "data:text/html,",
        },
        new String[] {
            "data:image/png,",
            "data:application/javascript,",
        },
        new String[] {
            "data:*/plain,",
            "data:%2a/plain,",
            "data:*/*,",
            "data:text/*,",
            "data:%2a/%2a,",
            "data:*/*,",
            "data:%2a/%2a,",
        });
  }

  @Test
  public void testMatchWithProperty() {
    runClassifierTests(
        MediaTypeClassifiers.builder()
        .type(MediaType.parse("text/plain;charset=UTF-8"))
        .build(),

        UrlContext.DEFAULT,

        new String[] {
            "data:text/plain;charset=UTF-8,",
            "data:text/plain;charset=\"UTF-8\",",
            "data:text/plain;charset=UTF-8;foo=bar,",
            "data:text/plain;foo=bar;charset=UTF-8,",
        },
        new String[] {
            "data:text/html,",
            "data:text/plain,",
            "data:tExt/Plain,",
            "data:text/plain;charset=ascii,",
            "data:text/plain;foo=bar,",
            "data:image/png,",
            "data:application/javascript,",
        },
        new String[] {
        });
  }

  @Test
  public void testAnyWithProperty() {
    runClassifierTests(
        MediaTypeClassifiers.builder()
        .type(MediaType.parse("*/*;evil=0"))
        .build(),

        UrlContext.DEFAULT,

        new String[] {
            "data:text/plain;evil=0;charset=UTF-8,",
            "data:text/plain;charset=\"UTF-8\";evil=0,",
            "data:image/png;evil=0,",
            "data:application/javascript;evil=0,",
        },
        new String[] {
            "data:text/plain,",
            "data:tExt/Plain,",
            "data:text/plain;charset=ascii,",
            "data:text/plain;foo=bar,",
            "data:image/png,",
            "data:application/javascript,",
            "data:image/png;base64;evil=0,",  // TODO: what should happen here?
        },
        new String[] {
        });
  }

}
