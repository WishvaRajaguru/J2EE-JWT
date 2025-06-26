package lk.rajaguru.web.app.security.servlet;

import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet("/login")
public class Login extends HttpServlet {

    @Inject
    private SecurityContext securityContext;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        System.out.println(username + " " + password);

        AuthenticationParameters credential = AuthenticationParameters.withParams().credential(new UsernamePasswordCredential(username, password));
        //THis will call the AuthMechanism once again, so be careful with white-listing
        AuthenticationStatus status = securityContext.authenticate(request, response, credential);

        if(AuthenticationStatus.SUCCESS.equals(status)) {
            response.sendRedirect(request.getContextPath() + "/");
        }else{
            response.sendRedirect(request.getContextPath() + "/auth/login.jsp");
        }
        System.out.println(status);
    }
}
