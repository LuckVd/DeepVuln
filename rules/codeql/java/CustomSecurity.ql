/**
 * @name SQL Injection via String Concatenation
 * @description Detects SQL injection vulnerabilities where user input is
 *              concatenated into SQL queries without proper sanitization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-056
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where
  config.hasFlowPath(source, sink) and
  // Additional custom filtering can be added here
  not source.getNode().getType().hasName("SafeString")
select sink.getNode(), source, sink, "SQL injection vulnerability from $@.",
  source.getNode(), "user input"
