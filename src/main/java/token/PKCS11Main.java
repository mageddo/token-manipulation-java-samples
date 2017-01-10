package token;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * @author elvis
 * @version $Revision: $<br/>
 *          $Id: $
 * @since 1/10/17 10:55 AM
 */
public class PKCS11Main {

    public static void main(String[] args)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException, InvalidKeyException, SignatureException {


        // extraindo o certificado
        String configName = "/pkcs.cnf";
        String PIN = "123456";
        Provider p = new sun.security.pkcs11.SunPKCS11(Thread.class.getResourceAsStream(configName));
        Security.addProvider(p);
        KeyStore keyStore = KeyStore.getInstance("PKCS11");
        char[] pin = PIN.toCharArray();
        keyStore.load(null, pin);



        // extract the private key
        /*
         the token has many keys one from these is the private, everything what you need is identify her name
         and cast it
        */
        Enumeration aliasesEnum = keyStore.aliases();
        PrivateKey privateKey = null;
        while (aliasesEnum.hasMoreElements()) {
            final String alias = (String)aliasesEnum.nextElement();
            System.out.println("Alias: " + alias);
            final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            System.out.println("Certificate: " + cert);
            privateKey = (PrivateKey) keyStore.getKey(alias, null);
            System.out.println("Private key: " + privateKey);
        }

        // sign the file
        final Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(privateKey);

        FileInputStream fis = new FileInputStream(args[0]);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        bufin.close();

        // o retorno eh a assinatura
        final byte[] sign = dsa.sign();
    }
}
