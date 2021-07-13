package com.krazycrave.springsecurityazureb2coauthsvcs.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.interfaces.ECPrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtTokenStore {

    //Token sign key will be used to sign the JWT.
    // TODO: change this key later and place it in key vault.
    private final String tokenSignKey = "c5d4d70419bd4909a1e502812c6e1f2b";

    //Attributes from Authentication object and will put them in the JWT which
    // will be used later to construct the Authentication Object.
    private final String REG_ID = "clientRegistrationId";
    private final String NAMED_KEY = "namedAttributeKey";
    private final String AUTHORITIES = "authorities";
    private final String ATTRIBUTES = "attributes";

    /*
     * The generateToken method will accept Authentication object and build JWT token from that.
     */
    public String generateToken( Authentication authentication ) throws Exception {

        OAuth2AuthenticationToken token = ( OAuth2AuthenticationToken ) authentication;
        DefaultOAuth2User userDetails = ( DefaultOAuth2User ) token.getPrincipal();

        // Collecting all the authorities name.
        List<String> auths = userDetails.getAuthorities()
                .stream()
                .map( GrantedAuthority::getAuthority )
                .collect( Collectors.toList());

        /* Preparing JWT claims with values like Subject, Authorities, Attributes,
            NamedAttributeKey (required by DefaultOAuth2User), and token expire time
         */
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(  userDetails.getAttribute("oid").toString())
                .expirationTime( getDate( 5, ChronoUnit.HOURS ) )
                .claim( NAMED_KEY, "name" )
                .claim( ATTRIBUTES, userDetails.getAttributes() )
                .claim( AUTHORITIES, auths )
                .claim( REG_ID, token.getAuthorizedClientRegistrationId() )
                .build();

        // Prepare Sign key to Sign the JWT token
        ECKey key = new ECKeyGenerator( Curve.P_256 ).keyID( tokenSignKey ).generate();
        JWSHeader header = new JWSHeader.Builder( JWSAlgorithm.ES256 )
                .type( JOSEObjectType.JWT )
                .keyID( key.getKeyID() )
                .build();
        SignedJWT jwt = new SignedJWT( header, claimsSet );

        // Sign the token and return.
        jwt.sign( new ECDSASigner( (ECPrivateKey) key.toPrivateKey() ) );
        return jwt.serialize();
    }

    /*
     * getAuth method takes JWT token and prepares the Authentication object from the valid token.
     */
    public Authentication getAuthentication ( String jwt ) throws Exception {
        Assert.notNull(jwt, "json web token cannot be null");
        SignedJWT signedJWT = SignedJWT.parse( jwt );

        // Validating the JWT token currently validating the expireTime only,
        // TODO: need to update with custom validation logic.
        validateJwt( signedJWT );

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        // Get required objects from JWT claims which will be used to prepare Authentication token.
        String clientRegistrationId = (String ) claimsSet.getClaim( REG_ID );
        String namedAttributeKey = (String) claimsSet.getClaim( NAMED_KEY );
        Map<String, Object> attributes = (Map<String, Object>)claimsSet.getClaim( ATTRIBUTES );
        Collection<? extends GrantedAuthority > authorities =( (List<String> ) claimsSet.getClaim( AUTHORITIES ))
                .stream().map( SimpleGrantedAuthority::new ).collect( Collectors.toSet());

        // Prepare and return the valid OAuth2AuthenticationToken
        return new OAuth2AuthenticationToken(
                new DefaultOAuth2User( authorities, attributes, namedAttributeKey ),
                authorities,
                clientRegistrationId
        );
    }

    private Date getDate(int amount, ChronoUnit hours) {
        return Date.from(
                LocalDateTime.now()
                        .plus( amount, hours )
                        .atZone( ZoneId.systemDefault() )
                        .toInstant()
        );
    }

    private void validateJwt( JWT jwt ) throws Exception {
        // Validating the expirationTime with current time.
        if(jwt.getJWTClaimsSet().getExpirationTime().before( new Date() )){
            throw new RuntimeException("Token Expired!!");
        }

        // TODO: Add validation logic here..
    }
}
