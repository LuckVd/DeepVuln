/**
 * @name SQL Injection via String Concatenation
 * @description Detects SQL injection vulnerabilities in Go where user input
 *              is concatenated into SQL queries.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id go/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import semmle.go.dataflow.FlowSources
import semmle.go.security.SqlInjectionQuery

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.",
  source.getNode(), "user input"
