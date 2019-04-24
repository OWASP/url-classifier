package org.owasp.url;

public interface PunycodeIdentifier {
  boolean isPotentialHomograph(String name);
}
