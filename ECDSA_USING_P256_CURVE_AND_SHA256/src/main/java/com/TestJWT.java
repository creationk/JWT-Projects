package com;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;

public class TestJWT {
    public static void main (String [] args) throws JoseException, InvalidJwtException {
        String kid="123";
        long DELAY = 10;
        String algorithm = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;

        //Generate private and public keys
        EllipticCurveJsonWebKey jwkE = EcJwkGenerator.generateJwk((EllipticCurves.P256));
        jwkE.setKeyId(kid);
        jwkE.setAlgorithm(algorithm);
        String jsonPublicKey = jwkE.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        String jsonPrivateKey = jwkE.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        PrivateKey privateKey = new EllipticCurveJsonWebKey(JsonUtil.parseJson(jsonPrivateKey)).getEcPrivateKey();
        System.out.println("*********** KEYS ***********");
        System.out.println("jsonPublicKey:\t"+jsonPublicKey+"\njsonPrivateKey:\t"+jsonPrivateKey);

        //Prepare payload
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(DELAY);
        claims.setClaim("dummy_name","dummy value");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(algorithm);
        jws.setKeyIdHeaderValue(kid);
        jws.setPayload(claims.toJson());

        //Encode using the private key and serialize
        jws.setKey(privateKey);
        String token = jws.getCompactSerialization();

        //Decode at the consumer end
        EllipticCurveJsonWebKey jwk = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(jsonPublicKey);
        JwtConsumer consumer = new JwtConsumerBuilder().setVerificationKey(jwk.getKey()).setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,algorithm)).build();
        JwtClaims decodedClaims = consumer.processToClaims(token);

        //Print claims
        System.out.println("Encoded claims:\n"+claims.toJson());
        System.out.println("Decoded claims:\n"+decodedClaims.toJson());
    }
}
