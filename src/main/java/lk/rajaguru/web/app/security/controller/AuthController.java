package lk.rajaguru.web.app.security.controller;

import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lk.rajaguru.web.app.security.security.Credential;
import lk.rajaguru.web.app.security.service.LoginService;
import lk.rajaguru.web.app.security.util.JWTUtil;

import java.util.Set;

@Path("/auth")
public class AuthController {

    @Inject
    private LoginService loginService;

    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(Credential credential) {
        if(loginService.validate(credential.getUsername(), credential.getPassword())) {
            Set<String> roles = loginService.getRoles(credential.getUsername());
            String token = JWTUtil.generateToken(credential.getUsername(), roles);

            JsonObject jsonObject = Json.createObjectBuilder().add("token", token).build();
            return Response.ok(jsonObject).build();
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String register(String username, String password) {
        return "Auth.register";
    }
}
