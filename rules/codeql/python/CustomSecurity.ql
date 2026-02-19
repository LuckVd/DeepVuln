/**
 * @name SQL Injection via String Format
 * @description Detects SQL injection vulnerabilities where user input is
 *              formatted into SQL queries using string formatting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id python/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("sqlite3").getMember("cursor").getMember("execute").getACall() and
      sink = call.getArg(0)
    )
    or
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("mysql").getMember("cursor").getMember("execute").getACall() and
      sink = call.getArg(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.",
  source.getNode(), "user input"
