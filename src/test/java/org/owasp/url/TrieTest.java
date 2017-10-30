package org.owasp.url;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

@SuppressWarnings("javadoc")
public class TrieTest {

  private long seed;

  @Before
  public void setUp() {
    String seedStr = System.getProperty("test.seed");
    seed = seedStr != null
        ? Long.parseLong(seedStr)
        : System.currentTimeMillis();
  }

  @Test
  public void testEquivalenceWithSortedMap() {
    boolean ok = false;
    try {
      Random prng = new Random(seed);
      for (int i = 0; i < 100; ++i) {
        runFuzzTests(prng);
      }
      ok = true;
    } finally {
      if (!ok) {
        System.out.println("Fuzz failure when run with seed " + seed);
        System.out.println("Run with -Dtest.seed=" + seed + " to reprpduce");
      }
    }
  }

  private static void runFuzzTests(Random prng) {
    Map<List<Integer>, Integer> hmap = new LinkedHashMap<List<Integer>, Integer>();
    for (int i = prng.nextInt(100); --i >= 0;) {
      List<Integer> keyEls = Lists.newArrayList();
      for (int j = prng.nextInt(10); --j >= 0;) {
        keyEls.add(prng.nextInt());
      }
      Integer value = prng.nextInt();
      hmap.put(keyEls, value);
    }
    ImmutableList<Map.Entry<List<Integer>, Integer>> entries = ImmutableList.copyOf(
        hmap.entrySet());
    Trie<Integer, Integer> trie = Trie.from(entries);
    for (Map.Entry<List<Integer>, Integer> e : entries) {
      Trie<Integer, Integer> t = trie;
      for (Integer el : e.getKey()) {
        t = t.els.get(el);
        assertNotNull(
            "Missing sub-tree for " + el + " in " + e.getKey()
            + " in trie created from " + hmap,
            t);
      }
      assertEquals(
          "Value mismatch for " + e.getKey() + " n trie created from " + hmap,
          e.getValue(), t.value);
    }
  }

}
