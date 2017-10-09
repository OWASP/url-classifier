# URL Classifier [![Build Status](https://travis-ci.org/OWASP/url-classifier.svg?branch=master)](https://travis-ci.org/OWASP/url-classifier)

Declarative syntax for defining sets of URLs.  No need for error-prone regexs.

  * [Usage](#usage)
  * [Problem](#problem)
  * [Simplifying Assumptions](#assumptions)

## <a name="usage"></a>Usage

### Java <sub><sup>([javadoc][javadoc])</sup></sub>

[javadoc]: http://static.javadoc.io/org.owasp/url/1.0.0/org/owasp/url/package-summary.html#package.description

```java
// Classes are all defined under org.owasp.url
import org.owasp.url.*;

class C {

  /** We define a classifier with a declarative syntax */
  static final UrlClassifier CLASSIFIER = UrlClassifier.builder()
      // We want to allow HTTP and HTTPS for this example
      .scheme(BuiltinScheme.HTTP, BuiltinScheme.HTTPS)
      .authority(
          AuthorityClassifier.builder()
          // We whitelist some subdomains of certain hosts
          .host("**.example.com", "**.example.net")
          .build())
      // We allow access to .html files
      .path("**.html")
      .build();

  void f() {
    // At runtime, we build a URL value.
    UrlValue url = UrlValue.from("http://example.com/");

    Classification c = CLASSIFIER.apply(
        url
        // If we want an explanation of why classification failed
        // we can connect diagnostics to our logs.
        Diagnostic.Receiver.NULL);

    // We can switch on the result.
    switch (c) {
      case MATCH:
        // ...
        System.out.println(url.urlText);
        break;
      case DOES_NOT_MATCH:
        // ...
        break;
      case INVALID:
        // ...
        break;
    }
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
