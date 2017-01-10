package token;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * @author elvis
 * @version $Revision: $<br/>
 *          $Id: $
 * @since 1/10/17 10:55 AM
 */
public class PKCS11Main {

    public static void main(String[] args)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

        String configName = "/pkcs.cnf";
        String PIN = "123456";
        Provider p = new sun.security.pkcs11.SunPKCS11(Thread.class.getResourceAsStream(configName));
        Security.addProvider(p);
        KeyStore keyStore = KeyStore.getInstance("PKCS11");
        char[] pin = PIN.toCharArray();
        keyStore.load(null, pin);
    }
}
