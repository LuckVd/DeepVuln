package bench.vuln.sqli;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** MINI benchmark: java/sqli (CWE-89) — vulnerable variant. 拼接 SQL 后 Statement.execute。 */
public class UserQueryServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // Entry point: GET /user?id=<uid>
        String userId = req.getParameter("id");
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
                Statement stmt = conn.createStatement()) {
            String query = "SELECT name FROM users WHERE id = '" + userId + "'";
            ResultSet rs = stmt.execute(query) ? stmt.getResultSet() : null; // SINK: sql-injection (CWE-89)
            resp.getWriter().write(rs != null && rs.next() ? rs.getString(1) : "none");
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
