package bench.safe.cmdi;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * MINI benchmark: java/cmdi (CWE-78) — safe variant.
 * ProcessBuilder argv 直传 + 输入白名单正则校验。
 */
public class CmdExecServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Entry point: GET /cmdi?arg=<value>
        String userInput = req.getParameter("arg");
        if (userInput == null || !userInput.matches("[A-Za-z0-9._-]{1,64}")) { // SAFE: allowlist
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        ProcessBuilder pb = new ProcessBuilder("echo", userInput); // SAFE: direct argv
        pb.inheritIO();
        pb.start();
        resp.getWriter().write("done");
    }
}
