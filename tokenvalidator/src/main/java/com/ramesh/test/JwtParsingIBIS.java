package com.ramesh.test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class JwtParsingIBIS {

    public static void main(String[] args) throws Exception {

        //public key corresponding to the private key, which is used to sign the JWT by AUTH server
        String realmPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkj7JBvNsJYMkN9Axu2XMi7ial0xaawj0Yp1rqphhKWoBjSab3An6e29PfJ4OwVLbvF0BWI/6bDN2aSDWO1MFdHt4VOCy/BAbWEaz3kEPwVA10bitQo74KrFvF+85OZc8/QPsJBmVEXRGX6iION+48Yb+M1bq9IxENxDMoUdoj4lxw+4D8yXCHnVsbyR2F7IxgEBE39pQ/q+Gal3OJ/AMS0u1A69D++Rnqs4uWmcqN2qDb1IIIwo2B1J2FwJFVErBFK1BpxZ+ibtEzNPuhPotdn84vZ/IT9n8hINJUtKeFMzT7xRIKLEYS6KT6muezWySYtcf0KoLahdkrcVjB2+aTQIDAQAB";
        //Access token in jwt format
        String accessToken = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIzZGQ1MWRlOC04MWI1LTQyMGUtODNkZS1jNzBmODA0OWE3NzAiLCJleHAiOjE1MzkxMDMzODEsIm5iZiI6MCwiaWF0IjoxNTM5MDk2MTgxLCJpc3MiOiJodHRwOi8vcHJlLWliaXNhdXRoLmNvcnAuaWJlcmlhLmVzL2F1dGgvcmVhbG1zL2NvbW1lcmNpYWxfcGxhdGZvcm0iLCJhdWQiOiJpYmVyaWFfd2ViIiwic3ViIjoiNjZmNzliNzgtNmQ1Yy00NGQ1LTkzMzgtNGRmNzNiYTNiNTUyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiaWJlcmlhX3dlYiIsInNlc3Npb25fc3RhdGUiOiJkNTgxMjZmZi0zNGI5LTRiYzktYmU1ZS05NTVkYTk0OGRmODYiLCJjbGllbnRfc2Vzc2lvbiI6IjRhYWU1MTQ5LTY4ZWYtNDk3NS1hNTNhLTdiYTZlNmM4Yjg0ZCIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJST0xFX1JFVFJJRVZFX0RFTEFZRURfQkFHX1JFVElSRURfUkVDT1JEIiwiUk9MRV9DUkVBVEVfQ0xBSU0iLCJST0xFX0NMSUVOVF9XRUIiLCJST0xFX09STSIsIlJPTEVfQlBNIiwiUk9MRV9QTVQiLCJST0xFX0FWTSIsIlJPTEVfTE9DIiwiUk9MRV9SRVFVRVNUX0dDX0JBR19DTEFJTSIsIlJPTEVfQ0hFQ0tfUElSU1RBVFVTIiwiUk9MRV9BRFZNIiwiUk9MRV9SRVFVRVNUX1NVUFBPUlRfQ0FMTCIsIlJPTEVfUFJNIiwiUk9MRV9GQVNTIiwiUk9MRV9DVVNUIiwiUk9MRV9QQUNDIiwiUk9MRV9JRENfU0VBUkNIX0NVU1RPTUVSIiwiUk9MRV9SRVRSSUVWRV9EQU1BR0VEX0JBR19SRVRJUkVEX1JFQ09SRCIsIlJPTEVfQVBJTSIsIlJPTEVfUkVUUklFVkVfREVMQVlFRF9CQUciLCJST0xFX1JFVFJJRVZFX0RBTUFHRURfQkFHIiwiUk9MRV9TRUFUUyIsIlJPTEVfU1JWIiwiUk9MRV9HRVRfQ0xBSU1fU1RBVFVTIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJ2aWV3LXByb2ZpbGUiLCJtYW5hZ2UtYWNjb3VudCJdfX0sImVtYWlsIjoic2VydmljZS1hY2NvdW50LWliZXJpYV93ZWJAcGxhY2Vob2xkZXIub3JnIiwibmFtZSI6IiIsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1pYmVyaWFfd2ViIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMS4xODAuOSIsImNsaWVudEhvc3QiOiIxNzIuMjEuMTgwLjkiLCJjbGllbnRJZCI6ImliZXJpYV93ZWIifQ.S2VpKYFpxAMJpJmNLUjdjAAnzD7luBx8no8cU5tmZhGHSKUEryLILSDC8JJjwoqcSduhtd1_xTGh0sHeUiw_luOsQaRmnMrnxQyWsogLpzXOWqdyv34xmtbN7Q8pvlN56NdNzDjvLokafK2etRDFR3p0Ti-VW1xOzXt1CeSlIC4-LU0lFyg5qRvAHfAC64e2eokZt-ndo-hTZa0MgmlQ1RP7rs_WWA_gpDlbjjxK8uwpdGuYPM2gJLAm9bK4L_1iV_GXP4RdXXSHiAsNMBh3ZsJkiSNOjvMWcU26afrxI_Dba_L5d2jxSLL4HKQy1M3hAEdZwj0wc52KY1s1j8AeHg";

        // Coveert the public key to the der format which is expected by JWT parser
        PublicKey publicKey = decodePublicKey(pemToDer(realmPublicKey));

        Jws<Claims> claimsJws = Jwts.parser() //
                .setSigningKey(publicKey) //
                .parseClaimsJws(accessToken) //
                ;
        System.out.println(claimsJws);
        //gives: header={alg=RS256},body={jti=f47335d5-9da0-4ada-a99f-4805a59ddba4, exp=1457366908, nbf=0, iat=1457366608, iss=http://login.acme.local:8081/auth/realms/acme, aud=vaadin-app, sub=65992f79-6382-4d98-9af2-90cf5f76fe91, typ=Bearer, azp=vaadin-app, session_state=12ee8e0f-d380-41fa-8311-c2b42368bff9, client_session=f7503bbd-ade6-4457-be21-4744d1bf1784, allowed-origins=[http://localhost:7777], resource_access={acme-petclinic={roles=[admin, user]}, vaadin-app={roles=[user]}, account={roles=[manage-account, view-profile]}}, name=Theo Tester, preferred_username=theo, given_name=Theo, family_name=Tester, email=tom+theo@localhost},signature=frMCkpDKG4VixXRZhh7KZqjDCxPbZq_6Wrl5X6RhjlGs9hL22Z6pcsVSlIzpincdwbLCpLYpLs3T2LRrlZ-YNUGOnKObnrmlVbMNi8UmGJiAj0bAsIPYWEfA-Ww3wuTitfjo0fgbAb8F_sLsPR9qjE6BcDPVXR2S_SJVWJ1CKb5kwiwKTTzAMUo1H22Ce64hoeSuEdQFM1x1n-M8kTkLPUPnL_lj-mOIpqbLZyrls3_TEL3up0-XYyF2Gt9fDQKXTp_XPLizGUiiY90TQC4rhNye3JPLMB6RZnQFmyJq5I5Cq0ybdMarloeLjvYjc3RyIgZgtFWjk5aNYDaietBJSA

    }

    /**
     * Decode a PEM string to DER format
     *
     * @param pem
     * @return
     * @throws IOException
     */
    public static byte[] pemToDer(String pem) throws IOException {
        return Base64.getDecoder().decode(stripBeginEnd(pem));
    }

    public static String stripBeginEnd(String pem) {

        String stripped = pem.replaceAll("-----BEGIN (.*)-----", "");
        stripped = stripped.replaceAll("-----END (.*)----", "");
        stripped = stripped.replaceAll("\r\n", "");
        stripped = stripped.replaceAll("\n", "");

        return stripped.trim();
    }


    public static PublicKey decodePublicKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);

        KeyFactory kf = KeyFactory.getInstance("RSA"
                //        , "BC" //use provider BouncyCastle if available.
        );

        return kf.generatePublic(spec);
    }
}