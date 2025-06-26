package lk.rajaguru.web.app.security.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import lk.rajaguru.web.app.security.service.LoginService;

import java.util.Set;

@ApplicationScoped
public class AppIdentityStore implements IdentityStore {

    @Inject
    private LoginService loginService;

    @Override
    public CredentialValidationResult validate(Credential credential) {

        if(credential instanceof UsernamePasswordCredential upc){
            boolean validate = loginService.validate(upc.getCaller(), upc.getPasswordAsString());
            if(validate){
                System.out.println("before roles get");
                Set<String> roles = loginService.getRoles(upc.getCaller());
                System.out.println("after roles get");
                return new CredentialValidationResult(upc.getCaller(), roles);
            }
        }
        return CredentialValidationResult.NOT_VALIDATED_RESULT;
    }
}
