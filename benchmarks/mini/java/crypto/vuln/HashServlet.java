package bench.vuln.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** MINI benchmark: java/crypto (CWE-327) — vulnerable variant。弱哈希 MD5 处理口令类输入。 */
public class HashServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Entry point: POST /hash?secret=<value>
        String secret = req.getParameter("secret");
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5"); // SINK: weak-hash (CWE-327)
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        byte[] digest = md.digest(secret.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        resp.getWriter().write(hex.toString());
    }
}
