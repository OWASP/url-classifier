
# URL Classifier [![Build Status](https://travis-ci.org/OWASP/url-classifier.svg?branch=master)](https://travis-ci.org/OWASP/url-classifier)

Declarative syntax for defining sets of URLs.  No need for error-prone regexs.

  * [Usage](#usage)
  * [Problem](#problem)
  * [Simplifying Assumptions](#assumptions)

## <a name="usage"></a>Usage <sub><sup>([javadoc][javadoc])</sup></sub>

[javadoc]: http://static.javadoc.io/org.owasp/url/1.2.2/org/owasp/url/package-summary.html#package.description

```java
// Classes are all defined under org.owasp.url
import org.owasp.url.*;

class C {

  /** We define a classifier with a declarative syntax */
  static final UrlClassifier CLASSIFIER = UrlClassifiers.builder()
      // We want to allow HTTP and HTTPS for this example
      .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
      .authority(
          AuthorityClassifiers.builder()
          // We whitelist some subdomains of hosts we trust.
          .host("**.example.com", "**.example.net")
          .build())
      // We allow access to .html files
      .pathGlob("**.html")
      .build();

  void f() {
    // At runtime, we build a URL value.
    // Pass in a URLContext if you know the base URL.
    UrlValue url = UrlValue.from("http://example.com/");

    Classification c = CLASSIFIER.apply(
        url,
        // If we want an explanation of why classification failed
        // we can connect diagnostics to our logs.
        Diagnostic.Receiver.NULL);

    // We can switch on the result.
    switch (c) {
      case MATCH:
        // ...
        System.out.println(url.urlText);
        break;
      case NOT_A_MATCH:
        // ...
        break;
      case INVALID:
        // ...
        break;
    }
  }
}
```


## <a name="invalid"></a> Invalid URLs

A *UrlClassifier* returns `MATCH` for some URLs and `NOT_A_MATCH` for
others, but it can also return `INVALID`.  An `INVALID` URL is one that

  * Is not syntactically valid per specifications and which is not
    coerced consistently to a valid URL by tolerant parsers.<br>
    `http:/foo` is invalid.  Although it is
    syntactically valid according to STD 66, it is missing a host
    required by RFC 7230 which defines the `http` protocol.<br>
    `http://例/` is valid even though it is rejected by
    a strict interpretation of STD 66 because there is a
    widely & consistently implemented way of handling non-ASCII
    characters in host names.
  * Or is valid per specifications, but is not consistently
    handled by implementations, and/or has negative security
    consequences in many implementations.<br>
    For example, `http://example.com/../../../../etc/passwd` is
    equivalent to `http://example.com/etc/passwd` per the specification
    has been used in [dircectory traversal attacks][dir_traverse]).

[dir_traverse]: https://www.owasp.org/index.php/Path_Traversal

There are several [corner cases](http://static.javadoc.io/org.owasp/url/1.2.2/org/owasp/url/UrlValue.CornerCase.html) that are rejected as `INVALID` by default.

If you need to treat one or more as valid, you can tell your *UrlClassifier*
to *tolerate* them thus:

```java
import static org.owasp.url.UrlValue.CornerCase.*;

{
  UrlClassifiers.builder()
      // Allow too many ..
      .tolerate(PATH_SIMPLIFICATION_REACHES_ROOT_PARENT)
      // More policy here ...
      .build();

  // Alternatively, if we're triggering this particular corner case
  // because the default context doesn't capture our application path
  // we can use a different context when classifying UrlValues.
  UrlContext context = UrlContext.DEFAULT.withContextUrl(
      "http://example.com/foo/bar/baz/");
}
```

## <a name="diagnostics"></a> Diagnostics

Sometimes its nice to know which URLs do not match a classifier and why.

You can tie UrlClassifiers into your logging framework by implementing
a [`Diagnostic.Receiver`](http://static.javadoc.io/org.owasp/url/1.2.2/org/owasp/url/Diagnostic.Receiver.html).

```java
Classification classifyNoisily(UrlClassifier c, UrlValue x) {
  return c.apply(
      x,
      (d, v) -> { System.err.println(v + " did not match due to " + d); }
      // Use your favorite logging framework instead of System.err.
      );
}

Classification classifyNoisilyOldStyle(UrlClassifier c, UrlValue x) {
  // Old style anonymous class.
  Diagnostic.Receiver<UrlValue> r = new Diagnostic.Receiver<UrlValue>() {
    @Override public void note(Diagnostic d, UrlValue x) {
      System.err.println(x + " did not match due to " + d);
    }
  };
  return c.apply(x, r);
}
```


## <a name="problem"></a>Problem

Matching URLs with regular expressions is hard.
Even experienced programmers who are familiar with the URL spec
produce patterns like `/http:\/\/example.com/` which spuriously
matches unintended URLs:

-  `http://example.com.evil.com/`
-  `http://example.com@evil.com/`
-  `http://example_com/`
-  `javascript:alert(1)//http://example.com`

while failing to match simple variants that probably should:

-  `HTTP://example.com/` which uses a ucase scheme
-  `http://EXAMPLE.com/` which uses a ucase hostname
-  `https://example.com/` which uses a scheme that is equivalent for most intents and purposes.

A common "fix" for that example, `/^https?:\/\/example\.com\//i`, spuriously fails to match
other variants:

-  `http://example.com./` which use a trailing dot to disable DNS suffix searching
-  `http://example.com:80/` which makes the port explicit

Epicycles can be added to a regex to work around problems as they're found but there is a tradeoff
between correctness and readability/maintainability.

There are similar hazards when trying to constrain other parts of the URL like the paths.
`/^(?:https?:\/\/example\.com)?\/foo\/.*/` looks like
it should match only URLs that have a path under `/foo/` but spuriously matches

-  `http://example.com/foo/../../../../etc/passed`

which, used in the wrong context, can cause [problems](https://en.wikipedia.org/wiki/Directory_traversal_attack)


## <a name="assumptions"></a>Simplifying Assumptions

### UTF-8 centric

We assume all `%`-sequences outside data or blob content can be
decoded into UTF-8 and mark as invalid any inputs that include
code-unit sequences that are not valid UTF-8 or that are not minimally
encoded.

### Empty domain search list

We assume that all hostnames are complete.
For example, `http://www/` might actually resolve to
`http://www.myorganization.org/`
after the domain search list is applied.
We can't do this and have stable predicates that do not depend on
external services and that do not potentially leak information about
servers inside a firewall to anyone outside the firewall who can
specify a partial URL.
