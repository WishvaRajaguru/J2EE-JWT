package lk.rajaguru.web.app.security.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import lk.rajaguru.web.app.security.util.JWTUtil;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@AutoApplySession
@ApplicationScoped
public class AuthMechanism implements HttpAuthenticationMechanism {

    @Inject
    private IdentityStore identityStore;

    public static final Set<String> WHITE_LIST = Set.of("/auth/login.jsp", "/auth/register.jsp", "/login");

    private boolean isWhiteListed(String url) {
        return WHITE_LIST.stream().anyMatch(url::equals);
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext context) throws AuthenticationException {

//        String url = request.getServletPath();
//        System.out.println("Path: " + url);
//        if (isWhiteListed(url)) {
//            System.out.println("From whitelist");
//            return context.doNothing();
//        }

        //the token based authentication part
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader != null && !authHeader.startsWith("Bearer ")) {
            try{
                String token = authHeader.replaceFirst("Bearer ", "");
                Claims claims = JWTUtil.parseToken(token).getPayload();
                String username = claims.getSubject();
                List roles = claims.get("roles", List.class);

                CredentialValidationResult result = new CredentialValidationResult(username, new HashSet<>(roles));
                return context.notifyContainerAboutLogin(result);
            }catch (JwtException e){
                return context.responseUnauthorized(); // invalid token
            }
        }

        //works for web resources validation (servlets, jsp, etc...)
        AuthenticationParameters authParameters = context.getAuthParameters();
        if(authParameters.getCredential() != null) {
            CredentialValidationResult result = identityStore.validate(authParameters.getCredential());
            if(result.getStatus() == CredentialValidationResult.Status.VALID) {
                // valid notify to continue
                return context.notifyContainerAboutLogin(result);
            }else {
                return AuthenticationStatus.SEND_FAILURE;
            }
        }

        // check whether the requested resource is protected && is the user already authenticated
        if(context.isProtected() && context.getCallerPrincipal() == null) {
            try {
                response.sendRedirect(request.getContextPath() + "/auth/login.jsp");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return AuthenticationStatus.SEND_CONTINUE;
        }

        return context.doNothing();
    }
}
