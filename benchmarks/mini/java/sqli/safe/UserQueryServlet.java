package bench.safe.sqli;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** MINI benchmark: java/sqli (CWE-89) — safe variant（PreparedStatement 参数化）。 */
public class UserQueryServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Entry point: GET /user?id=<uid>
        String userId = req.getParameter("id");
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
                PreparedStatement ps =
                        conn.prepareStatement("SELECT name FROM users WHERE id = ?")) { // SAFE
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                resp.getWriter().write(rs.next() ? rs.getString(1) : "none");
            }
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
