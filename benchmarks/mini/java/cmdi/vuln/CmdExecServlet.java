package bench.vuln.cmdi;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * MINI benchmark: java/cmdi (CWE-78) — vulnerable variant.
 *
 * 模式来源：OWASP BenchmarkJava testcode 同型 taint 流。
 * 链路：servlet doGet 参数（source）→ Runtime.exec 拼接命令（sink）。
 */
public class CmdExecServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Entry point: GET /cmdi?arg=<value>
        String userInput = req.getParameter("arg");
        Process proc =
                Runtime.getRuntime().exec("sh -c echo " + userInput); // SINK: command-injection (CWE-78)
        proc.destroy();
        resp.getWriter().write("done");
    }
}
