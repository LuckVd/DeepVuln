/**
 * @name SQL Injection via Template Literals
 * @description Detects SQL injection vulnerabilities where user input is
 *              interpolated into SQL queries using template literals.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id javascript/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript
import semmle.javascript.dataflow.FlowSources
import semmle.javascript.security.SqlInjectionQuery

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.",
  source.getNode(), "user input"
