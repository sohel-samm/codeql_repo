import java.sql.*;

public class VulnerableSQL {
    public static void main(String[] args) {
        String userInput = args.length > 0 ? args[0] : "admin";
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb", "root", "password");
            Statement stmt = conn.createStatement();
            // Vulnerable to SQL Injection
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("User: " + rs.getString("username"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
