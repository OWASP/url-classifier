package com.mikesamuel.url;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.mikesamuel.url.Scheme.SchemePart;

/**
 * The tables of test-cases are courtesy Mike J Brown from skew.org/uri/uri_tests.js
 * License: CC0 <https://creativecommons.org/publicdomain/zero/1.0/>
 */
@SuppressWarnings({ "static-method", "javadoc" })
public class AbsolutizerTest {

  static final String BASE_URI0 = "http://a/b/c/d;p?q";
  static final String BASE_URI1 = "http://a/b/c/d;p?q=1/2";
  static final String BASE_URI2 = "http://a/b/c/d;p=1/2?q";
  static final String BASE_URI3 = "fred:///s//a/b/c";
  static final String BASE_URI4 = "http:///s//a/b/c";

  // Comments after MVS are not part of the original.
  // [ref, base, expected]
  private static final String[][] absolutizeTestCases = {
      // Cases posted to the uri@w3.org list by Graham Klyne
      // http://lists.w3.org/Archives/Public/uri/2004Feb/0108.html
      // (1) base is invalid because it contains #frag, but can still be processed according to spec
      {"", "http://example.com/path?query#frag", "http://example.com/path?query"},
      // (2)
      // http://lists.w3.org/Archives/Public/uri/2004Feb/0114.html
      {"../c",  "foo:a/b", "foo:c"}, // Graham Klyne & Adam Costello expect foo:c, spec calls for foo:/c
      {"foo:.", "foo:a",   "foo:"},
      {"/foo/../../../bar", "zz:abc", "zz:/bar", "zz:///bar"},  // MVS added zz:///bar
      {"/foo/../bar",       "zz:abc", "zz:/bar", "zz:///bar"},  // MVS added zz:///bar
      {"foo/../../../bar",  "zz:abc", "zz:bar"},
      {"foo/../bar",        "zz:abc", "zz:bar"},
      {"zz:.",              "zz:abc", "zz:"},
      {"/."      , BASE_URI0, "http://a/"},
      {"/.foo"   , BASE_URI0, "http://a/.foo"},
      {".foo"    , BASE_URI0, "http://a/b/c/.foo"},

      // http://gbiv.com/protocols/uri/test/rel_examples1.html
      // examples from RFC 2396
      {"g:h"     , BASE_URI0, "g:h"},
      {"g"       , BASE_URI0, "http://a/b/c/g"},
      {"./g"     , BASE_URI0, "http://a/b/c/g"},
      {"g/"      , BASE_URI0, "http://a/b/c/g/"},
      {"/g"      , BASE_URI0, "http://a/g"},
      {"//g"     , BASE_URI0, "http://g"},
      // changed with RFC 2396bis
      //["?y"      , BASE_URI0, "http://a/b/c/d;p?y"},
      {"?y"      , BASE_URI0, "http://a/b/c/d;p?y"},
      {"g?y"     , BASE_URI0, "http://a/b/c/g?y"},
      // changed with RFC 2396bis
      //["#s"      , BASE_URI0, CURRENT_DOC_URI + "#s"},
      {"#s"      , BASE_URI0, "http://a/b/c/d;p?q#s"},
      {"g#s"     , BASE_URI0, "http://a/b/c/g#s"},
      {"g?y#s"   , BASE_URI0, "http://a/b/c/g?y#s"},
      {";x"      , BASE_URI0, "http://a/b/c/;x"},
      {"g;x"     , BASE_URI0, "http://a/b/c/g;x"},
      {"g;x?y#s" , BASE_URI0, "http://a/b/c/g;x?y#s"},
      // changed with RFC 2396bis
      //(""           , BASE_URI0, CURRENT_DOC_URI),
      {""     , BASE_URI0, "http://a/b/c/d;p?q"},
      {"."       , BASE_URI0, "http://a/b/c/"},
      {"./"      , BASE_URI0, "http://a/b/c/"},
      {".."      , BASE_URI0, "http://a/b/"},
      {"../"     , BASE_URI0, "http://a/b/"},
      {"../g"    , BASE_URI0, "http://a/b/g"},
      {"../.."   , BASE_URI0, "http://a/"},
      {"../../"  , BASE_URI0, "http://a/"},
      {"../../g" , BASE_URI0, "http://a/g"},
      {"../../../g", BASE_URI0, "http://a/../g", "http://a/g"},
      {"../../../../g", BASE_URI0, "http://a/../../g", "http://a/g"},
      // changed with RFC 2396bis
      //["/./g", BASE_URI0, "http://a/./g"},
      {"/./g", BASE_URI0, "http://a/g"},
      // changed with RFC 2396bis
      //["/../g", BASE_URI0, "http://a/../g"},
      {"/../g", BASE_URI0, "http://a/g"},
      {"g.", BASE_URI0, "http://a/b/c/g."},
      {".g", BASE_URI0, "http://a/b/c/.g"},
      {"g..", BASE_URI0, "http://a/b/c/g.."},
      {"..g", BASE_URI0, "http://a/b/c/..g"},
      {"./../g", BASE_URI0, "http://a/b/g"},
      {"./g/.", BASE_URI0, "http://a/b/c/g/"},
      {"g/./h", BASE_URI0, "http://a/b/c/g/h"},
      {"g/../h", BASE_URI0, "http://a/b/c/h"},
      {"g;x=1/./y", BASE_URI0, "http://a/b/c/g;x=1/y"},
      {"g;x=1/../y", BASE_URI0, "http://a/b/c/y"},
      {"g?y/./x", BASE_URI0, "http://a/b/c/g?y/./x"},
      {"g?y/../x", BASE_URI0, "http://a/b/c/g?y/../x"},
      {"g#s/./x", BASE_URI0, "http://a/b/c/g#s/./x"},
      {"g#s/../x", BASE_URI0, "http://a/b/c/g#s/../x"},
      {"http:g", BASE_URI0, "http:g", "http://a/b/c/g"},
      {"http:", BASE_URI0, "http:", BASE_URI0},

      // not sure where this one originated
      {"/a/b/c/./../../g", BASE_URI0, "http://a/a/g"},

      // http://web.archive.org/web/20060814021626/http://gbiv.com/protocols/uri/test/rel_examples2.html
      // slashes in base URI"s query args
      {"g"       , BASE_URI1, "http://a/b/c/g"},
      {"./g"     , BASE_URI1, "http://a/b/c/g"},
      {"g/"      , BASE_URI1, "http://a/b/c/g/"},
      {"/g"      , BASE_URI1, "http://a/g"},
      {"//g"     , BASE_URI1, "http://g"},
      // changed in RFC 2396bis
      //("?y"      , BASE_URI1, "http://a/b/c/?y"),
      {"?y"      , BASE_URI1, "http://a/b/c/d;p?y"},
      {"g?y"     , BASE_URI1, "http://a/b/c/g?y"},
      {"g?y/./x" , BASE_URI1, "http://a/b/c/g?y/./x"},
      {"g?y/../x", BASE_URI1, "http://a/b/c/g?y/../x"},
      {"g#s"     , BASE_URI1, "http://a/b/c/g#s"},
      {"g#s/./x" , BASE_URI1, "http://a/b/c/g#s/./x"},
      {"g#s/../x", BASE_URI1, "http://a/b/c/g#s/../x"},
      {"./"      , BASE_URI1, "http://a/b/c/"},
      {"../"     , BASE_URI1, "http://a/b/"},
      {"../g"    , BASE_URI1, "http://a/b/g"},
      {"../../"  , BASE_URI1, "http://a/"},
      {"../../g" , BASE_URI1, "http://a/g"},

      // http://web.archive.org/web/20070609062700/http://gbiv.com/protocols/uri/test/rel_examples3.html
      // slashes in path params
      // all of these changed in RFC 2396bis
      {"g"       , BASE_URI2, "http://a/b/c/d;p=1/g"},
      {"./g"     , BASE_URI2, "http://a/b/c/d;p=1/g"},
      {"g/"      , BASE_URI2, "http://a/b/c/d;p=1/g/"},
      {"g?y"     , BASE_URI2, "http://a/b/c/d;p=1/g?y"},
      {";x"      , BASE_URI2, "http://a/b/c/d;p=1/;x"},
      {"g;x"     , BASE_URI2, "http://a/b/c/d;p=1/g;x"},
      {"g;x=1/./y", BASE_URI2, "http://a/b/c/d;p=1/g;x=1/y"},
      {"g;x=1/../y", BASE_URI2, "http://a/b/c/d;p=1/y"},
      {"./"      , BASE_URI2, "http://a/b/c/d;p=1/"},
      {"../"     , BASE_URI2, "http://a/b/c/"},
      {"../g"    , BASE_URI2, "http://a/b/c/g"},
      {"../../"  , BASE_URI2, "http://a/b/"},
      {"../../g" , BASE_URI2, "http://a/b/g"},

      // http://web.archive.org/web/20070609062700/http://gbiv.com/protocols/uri/test/rel_examples4.html
      // double and triple slash, unknown scheme
      {"g:h"     , BASE_URI3, "g:h"},
      {"g"       , BASE_URI3, "fred:///s//a/b/g"},
      {"./g"     , BASE_URI3, "fred:///s//a/b/g"},
      {"g/"      , BASE_URI3, "fred:///s//a/b/g/"},
      {"/g"      , BASE_URI3, "fred:///g"},  // may change to fred:///s//a/g
      {"//g"     , BASE_URI3, "fred://g"},   // may change to fred:///s//g
      {"//g/x"   , BASE_URI3, "fred://g/x"}, // may change to fred:///s//g/x
      {"///g"    , BASE_URI3, "fred:///g"},
      {"./"      , BASE_URI3, "fred:///s//a/b/"},
      {"../"     , BASE_URI3, "fred:///s//a/"},
      {"../g"    , BASE_URI3, "fred:///s//a/g"},
      {"../../"  , BASE_URI3, "fred:///s//"},    // may change to fred:///s//a/../
      {"../../g" , BASE_URI3, "fred:///s//g"},   // may change to fred:///s//a/../g
      {"../../../g", BASE_URI3, "fred:///s/g"},  // may change to fred:///s//a/../../g
      {"../../../../g", BASE_URI3, "fred:///g"}, // may change to fred:///s//a/../../../g

      // http://web.archive.org/web/20070609062700/http://gbiv.com/protocols/uri/test/rel_examples5.html
      // double and triple slash, well-known scheme
      {"g:h"     , BASE_URI4, "g:h"},
      {"g"       , BASE_URI4, "http:///s//a/b/g"},
      {"./g"     , BASE_URI4, "http:///s//a/b/g"},
      {"g/"      , BASE_URI4, "http:///s//a/b/g/"},
      {"/g"      , BASE_URI4, "http:///g"},  // may change to http:///s//a/g
      {"//g"     , BASE_URI4, "http://g"},   // may change to http:///s//g
      {"//g/x"   , BASE_URI4, "http://g/x"}, // may change to http:///s//g/x
      {"///g"    , BASE_URI4, "http:///g"},
      {"./"      , BASE_URI4, "http:///s//a/b/"},
      {"../"     , BASE_URI4, "http:///s//a/"},
      {"../g"    , BASE_URI4, "http:///s//a/g"},
      {"../../"  , BASE_URI4, "http:///s//"},    // may change to http:///s//a/../
      {"../../g" , BASE_URI4, "http:///s//g"},   // may change to http:///s//a/../g
      {"../../../g", BASE_URI4, "http:///s/g"},  // may change to http:///s//a/../../g
      {"../../../../g", BASE_URI4, "http:///g"}, // may change to http:///s//a/../../../g

      // http://www.w3.org/2000/10/swap/uripath.py
      // version "$Id: uripath.py,v 1.21 2007/06/26 02:36:16 syosi Exp $"
      // 1. Dan Connelly's cases
      {"bar:abc", "foo:xyz", "bar:abc"},
      {"../abc", "http://example/x/y/z", "http://example/x/abc"},
      {"http://example/x/abc", "http://example2/x/y/z", "http://example/x/abc"},
      {"../r", "http://ex/x/y/z", "http://ex/x/r"},
      // This next one is commented out in uripath.py - why?
      // {"../../r", "http://ex/x/y/z", "http://ex/r"},
      {"q/r", "http://ex/x/y", "http://ex/x/q/r"},
      {"q/r#s", "http://ex/x/y", "http://ex/x/q/r#s"},
      {"q/r#s/t", "http://ex/x/y", "http://ex/x/q/r#s/t"},
      {"ftp://ex/x/q/r", "http://ex/x/y", "ftp://ex/x/q/r"},
      {"", "http://ex/x/y", "http://ex/x/y"},
      {"", "http://ex/x/y/", "http://ex/x/y/"},
      {"", "http://ex/x/y/pdq", "http://ex/x/y/pdq"},
      {"z/", "http://ex/x/y/", "http://ex/x/y/z/"},
      {"#Animal", "file:/swap/test/animal.rdf",
        "file:/swap/test/animal.rdf#Animal", "file:///swap/test/animal.rdf#Animal"},  // MVS added last
      {"../abc", "file:/e/x/y/z", "file:/e/x/abc", "file:///e/x/abc"},  // MVS added last
      {"/example/x/abc", "file:/example2/x/y/z", "file:/example/x/abc", "file:///example/x/abc"},  // MVS added last
      {"../r", "file:/ex/x/y/z", "file:/ex/x/r", "file:///ex/x/r"},  // MVS added last
      {"/r", "file:/ex/x/y/z", "file:/r", "file:///r"},  // MVS added last
      {"q/r", "file:/ex/x/y", "file:/ex/x/q/r", "file:///ex/x/q/r"},  // MVS added last
      {"q/r#s", "file:/ex/x/y", "file:/ex/x/q/r#s", "file:///ex/x/q/r#s"},  // MVS added last
      {"q/r#", "file:/ex/x/y", "file:/ex/x/q/r#", "file:///ex/x/q/r#"},  // MVS added last
      {"q/r#s/t", "file:/ex/x/y", "file:/ex/x/q/r#s/t", "file:///ex/x/q/r#s/t"},  // MVS added last
      {"ftp://ex/x/q/r", "file:/ex/x/y", "ftp://ex/x/q/r"},  // MVS added last
      {"", "file:/ex/x/y", "file:/ex/x/y", "file:///ex/x/y"},  // MVS added last
      {"", "file:/ex/x/y/", "file:/ex/x/y/", "file:///ex/x/y/"},  // MVS added last
      {"", "file:/ex/x/y/pdq", "file:/ex/x/y/pdq", "file:///ex/x/y/pdq"},  // MVS added last
      {"z/", "file:/ex/x/y/", "file:/ex/x/y/z/", "file:///ex/x/y/z/"},  // MVS added last
      {"file://meetings.example.com/cal#m1", "file:/devel/WWW/2000/10/swap/test/reluri-1.n3", "file://meetings.example.com/cal#m1"},
      {"file://meetings.example.com/cal#m1", "file:/home/connolly/w3ccvs/WWW/2000/10/swap/test/reluri-1.n3", "file://meetings.example.com/cal#m1"},
      {"./#blort", "file:/some/dir/foo", "file:/some/dir/#blort", "file:///some/dir/#blort"},  // MVS added last
      {"./#", "file:/some/dir/foo", "file:/some/dir/#", "file:///some/dir/#"},  // MVS added last
      // 2. Graham Klyne's cases - see below.
      // 3. Ryan Lee's case
      {"./", "http://example/x/abc.efg", "http://example/x/"},

      //
      // Graham Klyne's tests
      // <http://web.archive.org/web/20090228121430/http://www.ninebynine.org/Software/HaskellUtils/Network/UriTest.xls> internally dated 2004-04-20
      //
      // Relative01-31 are identical to Connolly's cases, except these:
      {"//example/x/abc", "http://example2/x/y/z", "http://example/x/abc"},     // Relative03
      {"/r", "http://ex/x/y/z", "http://ex/r"},                                 // Relative05
      // Relative32-49
      {"./q:r", "http://ex/x/y", "http://ex/x/q:r"},
      {"./p=q:r", "http://ex/x/y", "http://ex/x/p=q:r"},
      {"?pp/rr", "http://ex/x/y?pp/qq", "http://ex/x/y?pp/rr"},
      {"y/z", "http://ex/x/y?pp/qq", "http://ex/x/y/z"},
      {"local/qual@domain.org#frag", "mailto:local", "mailto:local/qual@domain.org#frag"},
      //{"more/qual2@domain2.org#frag", "mailto:local/qual1@domain1.org", "mailto:local/more/qual2@domain2.org#frag"},  // MVS: disabled.  TODO: wtf?
      {"y?q", "http://ex/x/y?q", "http://ex/x/y?q"},
      {"/x/y?q", "http://ex?p", "http://ex/x/y?q"},
      {"c/d",  "foo:a/b", "foo:a/c/d"},
      {"/c/d", "foo:a/b", "foo:/c/d", "foo:///c/d"},  // MVS added last
      {"", "foo:a/b?c#d", "foo:a/b?c"},
      {"b/c", "foo:a", "foo:b/c"},
      {"../b/c", "foo:/a/y/z", "foo:/a/b/c", "foo:///a/b/c"},  // MVS added last
      {"./b/c", "foo:a", "foo:b/c"},
      {"/./b/c", "foo:a", "foo:/b/c", "foo:///b/c"},  // MVS added last
      {"../../d", "foo://a//b/c", "foo://a/d"},
      {".", "foo:a", "foo:"},
      {"..", "foo:a", "foo:"},
      //
      // Relative50-57 (cf. TimBL comments:
      //  http://lists.w3.org/Archives/Public/uri/2003Feb/0028.html,
      //  http://lists.w3.org/Archives/Public/uri/2003Jan/0008.html)
      // 50, 53, 55, 56 are also in http://www.w3.org/2000/10/swap/uripath.py
      {"abc", "http://example/x/y%2Fz", "http://example/x/abc"},
      {"../../x%2Fabc", "http://example/a/x/y/z", "http://example/a/x%2Fabc"},
      {"../x%2Fabc", "http://example/a/x/y%2Fz", "http://example/a/x%2Fabc"},
      {"abc", "http://example/x%2Fy/z", "http://example/x%2Fy/abc"},
      {"q%3Ar", "http://ex/x/y", "http://ex/x/q%3Ar"},
      {"/x%2Fabc", "http://example/x/y%2Fz", "http://example/x%2Fabc"},
      {"/x%2Fabc", "http://example/x/y/z", "http://example/x%2Fabc"},
      //["/x%2Fabc", "http://example/x/y%2Fz", "http://example/x%2Fabc"}, // same as 55

      //
      // Relative70-77
      {"local2@domain2", "mailto:local1@domain1?query1", "mailto:local2@domain2"},
      {"local2@domain2?query2", "mailto:local1@domain1", "mailto:local2@domain2?query2"},
      {"local2@domain2?query2", "mailto:local1@domain1?query1", "mailto:local2@domain2?query2"},
      {"?query2", "mailto:local@domain?query1", "mailto:local@domain?query2"},
      {"local@domain?query2", "mailto:?query1", "mailto:local@domain?query2"},
      {"?query2", "mailto:local@domain?query1", "mailto:local@domain?query2"},
      {"http://example/a/b?c/../d", "foo:bar", "http://example/a/b?c/../d"},
      {"http://example/a/b#c/../d", "foo:bar", "http://example/a/b#c/../d"},
      //
      // Relative82-88
      {"http:this", "http://example.org/base/uri", "http:this"},
      {"http:this", "http:base", "http:this"},
      {".//g", "f:/a", /*"f://g",*/ "f:////g"},  // MVS added last.  Removed first.  See https://github.com/mjb2010/JS-URI-resolver-tester/issues/1
      {"b/c//d/e", "f://example.org/base/a", "f://example.org/base/b/c//d/e"},
      {"m2@example.ord/c2@example.org", "mid:m@example.ord/c@example.org", "mid:m@example.ord/m2@example.ord/c2@example.org"},
      {"mini1.xml", "file:///C:/DEV/Haskell/lib/HXmlToolbox-3.01/examples/", "file:///C:/DEV/Haskell/lib/HXmlToolbox-3.01/examples/mini1.xml"},
      {"../b/c", "foo:a/y/z", "foo:a/b/c"},

      // Mike Brown 2011-12-14
      // testing Merge Paths routine in STD 66
      {"b", "foo:", "foo:b"},
      {"b", "foo://a", "foo://a/b"},
      {"b", "foo://a?q", "foo://a/b"},
      {"b?q", "foo://a", "foo://a/b?q"},
      {"b?q", "foo://a?r", "foo://a/b?q"},

      // Mike Samuel 2014-07-17
      {"%2F", "http://example.org/foo/bar", "http://example.org/foo/%2F"},
      {"a%2Fb/..", "http://example.org/foo/bar", "http://example.org/foo/"},
      {".%2E", "http://example.org/foo/bar/", "http://example.org/foo/bar/.%2E"},
      {"%2e%2E", "http://example.org/foo/bar/", "http://example.org/foo/bar/%2e%2E"},
      {"%2E", "http://example.org/foo/bar/", "http://example.org/foo/bar/%2E"},
      // a normalizing resolver might produce different results, like this:
      //[".%2E", "http://example.org/foo/bar/", "http://example.org/foo/"},
      //["%2e%2E", "http://example.org/foo/bar/", "http://example.org/foo/"},
      //["%2E", "http://example.org/foo/bar/", "http://example.org/foo/bar/"}
  };

  @Test
  public void testMikeBrownCanBreakMyCode() {
    int nFailures = 0, n = absolutizeTestCases.length;
    for (int i = 0; i < n; ++i) {
      if (runTestCase(i)) { ++nFailures; }
    }
    if (nFailures != 0) {
      fail(nFailures + " / " + n);
    }
  }

  private static final SchemeLookupTable SCHEMES = new SchemeLookupTable(
      ImmutableList.of(
          new Scheme(ImmutableSet.of("foo"), true, -1, SchemePart.PATH, SchemePart.QUERY),
          new Scheme(ImmutableSet.of("fred"), true, -1, SchemePart.PATH, SchemePart.QUERY),
          new Scheme(ImmutableSet.of("f"), true, -1,
              SchemePart.AUTHORITY, SchemePart.PATH, SchemePart.QUERY),
          new Scheme(ImmutableSet.of("g"), true, -1,
              SchemePart.AUTHORITY, SchemePart.PATH, SchemePart.QUERY),
          new Scheme(ImmutableSet.of("mid"), true, -1,
              SchemePart.PATH, SchemePart.QUERY),
          new Scheme(ImmutableSet.of("zz"), true, -1,
              SchemePart.PATH, SchemePart.QUERY)
          ));

  private boolean runTestCase(int i) {
    String[] absolutizeTestCase = absolutizeTestCases[i];
    String testInput = absolutizeTestCase[0];
    String base = absolutizeTestCase[1];
    ImmutableSet<String> wants = ImmutableSet.copyOf(
        Arrays.asList(absolutizeTestCase).subList(2, absolutizeTestCase.length));
    Absolutizer abs;
    try {
      abs = new Absolutizer(SCHEMES, base);
    } catch (IllegalArgumentException ex) {
      System.err.println("#" + i + ": failed abnormally on `" + base + "`");
      ex.printStackTrace();
      return true;
    }
    String got;
    try {
      Absolutizer.Result result = abs.absolutize(testInput);
      got = result.absUrlText;
    } catch (RuntimeException ex) {
      System.err.println(
          "#" + i + ": abs(`" + testInput + "`) relative to `" + base + "`");
      ex.printStackTrace();
      return true;
    }
    if (!wants.contains(got)) {
      System.err.println(
          "#" + i + ": abs(`" + testInput + "`) relative to `" + base
          + "` => `" + got + "`");
      for (String want : wants) {
        System.err.println("\tNot `" + want + "`");
      }
      return true;
    }
    return false;
  }


  private void assertNorm(String want, String inp) {
    for (String prefix : new String[] { "", "foo", "/foo/" }) {
      StringBuilder buf = new StringBuilder().append(prefix).append(inp);
      Absolutizer.removeDotSegmentsInPlace(buf, prefix.length());
      String str = buf.toString();
      assertTrue(
          "`" + inp + "` with prefix `" + prefix + "` => `" + str + "`",
          str.startsWith(prefix));
      String got = str.substring(prefix.length());
      assertEquals("`" + inp + "` using prefix `" + prefix + "`", want, got);
    }
  }

  @Test
  public void testRemoveDotSegments() {
    assertNorm("", "");
    assertNorm("/", "/");
    assertNorm("/foo", "/foo");
    assertNorm("/foo/", "/foo/");
    assertNorm("//foo/", "//foo/");
    assertNorm("/foo///", "/foo///");
    assertNorm("/foo//", "/foo///..");
    assertNorm("/foo/", "/foo///../..");
    assertNorm("/", "/foo///../../..");
    assertNorm("", ".");
    assertNorm("", "..");
    assertNorm("", "../.");
    assertNorm("", "./..");
    assertNorm("/foo/bar", "/foo/./bar");
    assertNorm("/foo/bar/", "/foo/bar/.");
    assertNorm("/foo/bar/", "/foo/bar/./");
    assertNorm("/bar/", "/foo/../bar/");
    assertNorm("/bar/", "/foo/../../bar/");
    assertNorm("/bar/", "/foo/../..//../bar/");
    assertNorm("/", "/foo/../..//../");
    assertNorm("/foo/", "/foo/bar/..");
    assertNorm("/foo/.../bar", "/foo/.../bar");
    assertNorm("bar", "foo/../bar");
    assertNorm("foo/bar", "foo/./bar");
    assertNorm("", "foo/../..");
    assertNorm("/", "/.");
    assertNorm("/", "/./");
    assertNorm("/foo", "/./foo");
    assertNorm("a/b/c", "a/y/../b/c");
  }

  private static void assertEncDotFixup(String want, String inp) {
    for (String prefix : new String[] { "", "foo", "%2e", "/." }) {
      StringBuilder sb = new StringBuilder()
          .append(prefix)
          .append(inp);
      boolean ambiguous = Absolutizer.fixupEncodedDots(sb, prefix.length());
      String prefixGot = sb.toString();
      assertEquals("prefix=" + prefix + ", inp=" + inp, !want.equals(inp), ambiguous);
      if (Absolutizer.RECODE_ENCODED_SPECIAL_PATH_SEGMENTS) {
        assertEquals("prefix=" + prefix + ", inp=" + inp, prefix + want, prefixGot);
      } else {
        assertEquals("prefix=" + prefix + ", inp=" + inp, prefix + inp, prefixGot);
      }
    }
  }

  @Test
  public final void testDotFixup() {
    assertEncDotFixup("", "");
    assertEncDotFixup(".", ".");
    assertEncDotFixup(".", "%2e");
    assertEncDotFixup("..", "%2e%2e");
    assertEncDotFixup("..", ".%2e");
    assertEncDotFixup("..", "%2e.");
    assertEncDotFixup("..", "..");
    assertEncDotFixup("/.", "/.");
    assertEncDotFixup("/.", "/%2e");
    assertEncDotFixup("/..", "/%2e%2e");
    assertEncDotFixup("/..", "/.%2e");
    assertEncDotFixup("/..", "/%2e.");
    assertEncDotFixup("/..", "/..");
    assertEncDotFixup("/./", "/./");
    assertEncDotFixup("/./", "/%2e/");
    assertEncDotFixup("/../", "/%2e%2e/");
    assertEncDotFixup("/../", "/%2e%2E/");
    assertEncDotFixup("/../", "/%2E%2E/");
    assertEncDotFixup("/../", "/%2E%2E/");
    assertEncDotFixup("/../", "/.%2e/");
    assertEncDotFixup("/../", "/%2e./");
    assertEncDotFixup("/../", "/../");
    assertEncDotFixup("./", "./");
    assertEncDotFixup("./", "%2e/");
    assertEncDotFixup("../", "%2e%2e/");
    assertEncDotFixup("../", ".%2e/");
    assertEncDotFixup("../", "%2e./");
    assertEncDotFixup("../", "../");
    assertEncDotFixup("././../.", "%2e/%2e/%2e%2e/%2e");
    assertEncDotFixup("%2e%2e%2e", "%2e%2e%2e");
    assertEncDotFixup("%2e.%2e", "%2e.%2e");
    assertEncDotFixup("%2ef", "%2ef");
    assertEncDotFixup("f%2e", "f%2e");
    assertEncDotFixup("%2", "%2");
    assertEncDotFixup("%", "%");
  }
}
