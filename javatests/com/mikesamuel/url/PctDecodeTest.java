package com.mikesamuel.url;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.net.URLEncoder;

import org.junit.Test;

import com.google.common.base.Optional;

@SuppressWarnings({ "javadoc", "static-method" })
public final class PctDecodeTest {

  @Test
  public void testEmptyString() {
    assertEquals(Optional.of(""), PctDecode.of(""));
  }

  @Test
  public void testNoEncoding() {
    assertSame("foo", PctDecode.of("foo").get());
  }

  @Test
  public void testAmbiguous() {
    assertEquals(Optional.of("+"), PctDecode.of("+"));
  }

  @Test
  public void testSimpleExample() {
    assertEquals(Optional.of("Fran\u00e7ois"), PctDecode.of("Fran%c3%a7ois"));
    assertEquals(Optional.of("Fran\u00e7ois"), PctDecode.of("Fran%C3%A7ois"));
  }

  @Test
  public void testSingleCodepoints() throws Exception {
    for (int i = 0; i < 0x11000; ++i) {
      // skip
      if (i == ' ' || i == '+') {
        // Skip those ambiguous between %-encoding of form-encoded content
        // and other %-encoded content.
        continue;
      }
      if (i == 0xD800) {
        // skip surrogates
        i = 0xDFFF;
        continue;
      }
      String inp = new StringBuilder().appendCodePoint(i).toString();
      String enc = URLEncoder.encode(inp, "UTF-8");
      assertEquals(
          "U+" + Integer.toHexString(i),
          Optional.of(inp), PctDecode.of(enc));
    }
  }

  private static void assertSpaceDelim(String hexpairs, String want) {
    Optional<String> wantOpt = Optional.fromNullable(want);
    Optional<String> gotOpt = PctDecode.of(hexpairs.replace(' ', '%'));
    if (wantOpt.isPresent() && gotOpt.isPresent()) {
      assertEquals(wantOpt.get(), gotOpt.get());
    }
    assertEquals(wantOpt, gotOpt);
  }

  private static void assertSpaceDelim(String hexpairs, int cp0, int... cps) {
    StringBuilder sb = new StringBuilder().appendCodePoint(cp0);
    for (int cp : cps) {
      sb.appendCodePoint(cp);
    }
    assertSpaceDelim(hexpairs, sb.toString());
  }

  private static void assertSpaceDelim(String hexpairs) {
    assertSpaceDelim(hexpairs, null);
  }

  @Test
  public void testMarkusKuhnsAbilityToBreakMyCode() {
    // Courtesy http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
    assertSpaceDelim(
        " ce ba e1 bd b9 cf 83 ce bc ce b5",
        "κόσμε");
    // 2.1
    assertSpaceDelim(" 00", 0x0);
    assertSpaceDelim(" c2 80", 0x80);
    assertSpaceDelim(" e0 a0 80", 0x0800);
    assertSpaceDelim(" f0 90 80 80", 0x10000);
    assertSpaceDelim(" f8 88 80 80 80");  // Overlong
    assertSpaceDelim(" fc 84 80 80 80 80");
    // 2.2
    assertSpaceDelim(" 7f", 0x7f);
    assertSpaceDelim(" df bf", 0x7ff);
    assertSpaceDelim(" ef bf bf", 0xffff);
    assertSpaceDelim(" f7 bf bf bf");
    assertSpaceDelim(" fb bf bf bf bf");
    assertSpaceDelim(" fd bf bf bf bf bf");
    // 2.3
    assertSpaceDelim(" ed 9f bf", 0xd7ff);
    assertSpaceDelim(" ee 80 80", 0xe000);
    assertSpaceDelim(" ef bf bd", 0xfffd);
    assertSpaceDelim(" f4 8f bf bf", 0x10ffff);
    assertSpaceDelim(" f4 90 80 80");
    // 3.1
    assertSpaceDelim(" 80");
    assertSpaceDelim(" bf");
    assertSpaceDelim(" 80 bf");
    assertSpaceDelim(" 80 bf 80");
    assertSpaceDelim(" 80 bf 80 bf");
    assertSpaceDelim(" 80 bf 80 bf 80");
    assertSpaceDelim(" 80 bf 80 bf 80 bf");
    assertSpaceDelim(" 80 bf 80 bf 80 bf 80");
    assertSpaceDelim(
        " 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        + " 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
        + " a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af"
        + " b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf");
    // 3.2
    assertSpaceDelim(
        " c0 20 c1 20 c2 20 c3 20 c4 20 c5 20 c6 20 c7 20"
        + " c8 20 c9 20 ca 20 cb 20 cc 20 cd 20 ce 20 cf 20"
        + " d0 20 d1 20 d2 20 d3 20 d4 20 d5 20 d6 20 d7 20"
        + " d8 20 d9 20 da 20 db 20 dc 20 dd 20 de 20 df 20");
    assertSpaceDelim(
        " e0 20 e1 20 e2 20 e3 20 e4 20 e5 20 e6 20 e7 20"
        + " e8 20 e9 20 ea 20 eb 20 ec 20 ed 20 ee 20 ef 20");
    assertSpaceDelim(
        " f0 20 f1 20 f2 20 f3 20  f4 20 f5 20 f6 20 f7 20");
    assertSpaceDelim(" f8 20 f9 20 fa 20 fb 20");
    assertSpaceDelim(" fc 20 fd 20");
    // 3.3
    assertSpaceDelim(" c0");
    assertSpaceDelim(" e0 80");
    assertSpaceDelim(" f0 80 80");
    assertSpaceDelim(" f8 80 80 80");
    assertSpaceDelim(" fc 80 80 80 80");
    assertSpaceDelim(" df");
    assertSpaceDelim(" ef bf");
    assertSpaceDelim(" f7 bf bf");
    assertSpaceDelim(" fb bf bf bf");
    assertSpaceDelim(" fd bf bf bf bf");
    // 3.4
    assertSpaceDelim(
        " c0 e0 80 f0 80 80 f8 80 80 80 fc 80"
        + " 80 80 80 df ef bf f7 bf  bf fb bf bf bf fd bf bf"
        + " bf bf");
    // 3.5
    assertSpaceDelim(" fe");
    assertSpaceDelim(" ff");
    assertSpaceDelim(" fe fe ff ff");
    // 4.1
    assertSpaceDelim(" c0 af");
    assertSpaceDelim(" e0 80 af");
    assertSpaceDelim(" f0 80 80 af");
    assertSpaceDelim(" f8 80 80 80 af");
    assertSpaceDelim(" fc 80 80 80 80 af");
    // 4.2
    assertSpaceDelim(" c1 bf");
    assertSpaceDelim(" e0 9f bf");
    assertSpaceDelim(" f0 8f bf bf");
    assertSpaceDelim(" f8 87 bf bf bf");
    assertSpaceDelim(" fc 83 bf bf bf bf");
    // 4.3
    assertSpaceDelim(" c0 80");
    assertSpaceDelim(" e0 80 80");
    assertSpaceDelim(" f0 80 80 80");
    assertSpaceDelim(" f8 80 80 80 80");
    assertSpaceDelim(" fc 80 80 80 80 80");
    // 5.1
    assertSpaceDelim(" ed a0 80");
    assertSpaceDelim(" ed ad bf");
    assertSpaceDelim(" ed ae 80");
    assertSpaceDelim(" ed af bf");
    assertSpaceDelim(" ed b0 80");
    assertSpaceDelim(" ed be 80");
    assertSpaceDelim(" ed bf bf");
    // 5.2
    assertSpaceDelim(" ed a0 80 ed b0 80");
    assertSpaceDelim(" ed a0 80 ed bf bf");
    assertSpaceDelim(" ed ad bf ed b0 80");
    assertSpaceDelim(" ed ad bf ed bf bf");
    assertSpaceDelim(" ed ae 80 ed b0 80");
    assertSpaceDelim(" ed ae 80 ed bf bf");
    assertSpaceDelim(" ed af bf ed b0 80");
    assertSpaceDelim(" ed af bf ed bf bf");
    // 5.3
    assertSpaceDelim(" ef bf be", 0xfffe);
    assertSpaceDelim(" ef bf bf", 0xffff);
    assertSpaceDelim(
        ""
        + " ef b7"
        + " 90 ef b7 91 ef b7 92 ef b7 93 ef b7 94 ef b7 95"
        + " ef b7 96 ef b7 97 ef b7 98 ef b7 99 ef b7 9a ef"
        + " b7 9b ef b7 9c ef b7 9d ef b7 9e ef b7 9f ef b7"
        + " a0 ef b7 a1 ef b7 a2 ef b7 a3 ef b7 a4 ef b7 a5"
        + " ef b7 a6 ef b7 a7 ef b7 a8 ef b7 a9 ef b7 aa ef"
        + " b7 ab ef b7 ac ef b7 ad ef b7 ae ef b7 af",
        0xfdd0, 0xfdd1, 0xfdd2, 0xfdd3,
        0xfdd4, 0xfdd5, 0xfdd6, 0xfdd7,
        0xfdd8, 0xfdd9, 0xfdda, 0xfddb,
        0xfddc, 0xfddd, 0xfdde, 0xfddf,
        0xfde0, 0xfde1, 0xfde2, 0xfde3,
        0xfde4, 0xfde5, 0xfde6, 0xfde7,
        0xfde8, 0xfde9, 0xfdea, 0xfdeb,
        0xfdec, 0xfded, 0xfdee, 0xfdef
        );
    assertSpaceDelim(
        ""
        + " f0 9f bf be f0 9f bf"
        + " bf f0 af bf be f0 af bf bf f0 bf bf be f0 bf bf"
        + " bf f1 8f bf be f1 8f bf bf f1 9f bf be f1 9f bf"
        + " bf f1 af bf be f1 af bf bf f1 bf bf be f1 bf bf"
        + " bf f2 8f bf be f2 8f bf bf"
        + " f2 9f bf be f2 9f bf bf f2"
        + " af bf be f2 af bf bf f2 bf bf be f2 bf bf bf f3"
        + " 8f bf be f3 8f bf bf f3 9f bf be f3 9f bf bf f3"
        + " af bf be f3 af bf bf f3 bf bf be f3 bf bf bf f4"
        + " 8f bf be f4 8f bf bf",
        0x1fffe, 0x1ffff,
        0x2fffe, 0x2ffff,
        0x3fffe, 0x3ffff,
        0x4fffe, 0x4ffff,
        0x5fffe, 0x5ffff,
        0x6fffe, 0x6ffff,
        0x7fffe, 0x7ffff,
        0x8fffe, 0x8ffff,
        0x9fffe, 0x9ffff,
        0xafffe, 0xaffff,
        0xbfffe, 0xbffff,
        0xcfffe, 0xcffff,
        0xdfffe, 0xdffff,
        0xefffe, 0xeffff,
        0xffffe, 0xfffff,
        0x10fffe, 0x10ffff
        );
  }
}
