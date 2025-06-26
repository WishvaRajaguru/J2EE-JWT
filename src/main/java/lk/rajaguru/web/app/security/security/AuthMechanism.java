package lk.rajaguru.web.app.security.security;

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

import java.io.IOException;
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

        String url = request.getServletPath();
        System.out.println("Path: " + url);

//        if (isWhiteListed(url)) {
//            System.out.println("From whitelist");
//            return context.doNothing();
//        }

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
