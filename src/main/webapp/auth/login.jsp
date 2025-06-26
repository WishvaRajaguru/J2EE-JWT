<%--
  Created by IntelliJ IDEA.
  User: rwish
  Date: 6/25/2025
  Time: 10:31 AM
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>This is Login!</h1>
    <form method="POST" action="${pageContext.servletContext.contextPath}/login">
        <table>
            <tr>
                <td>Username:</td>
                <td><input type="text" name="username" /></td>
            </tr>
            <tr>
                <td>Password:</td>
                <td><input type="password" name="password" /></td>
            </tr>
            <tr>
                <td><input type="submit" value="Login" /></td>
            </tr>
        </table>
    </form>
</body>
</html>
