import cryptid.CryptID;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.SecurityLevel;

import java.math.BigInteger;

public class Main{
    public static void main(String[] args) throws Exception{
        /*
            Create Bob and PKG
            Take message input from Bob alongside public key
            Pass Bob info to PKG to create Ciphertext
            Pass Ciphertext to Alice
            Alice requests private key, decrypts
            Print message to confirm
         */

        //Create PKG/IBE wrapper class for issuing private keys
        PKG pkg = new PKG();

        //Get instance of IBE in wrapper class for use in encrypting
        IdentityBasedEncryption ibe = pkg.getInstance();

        //Create CA
        CA certificateAuthority = new CA();

        //Create Bob and Alice and receive their credentials
        Client Bob = new Client("bob@gmail.com");
        Bob.requestCredential(certificateAuthority);

        Client Alice = new Client("alice@gmail.com");
        Alice.requestCredential(certificateAuthority);

        //Get blinded credentials
        BigInteger blinded_c_x = Alice.blindCredentialX();
        BigInteger blinded_c_y = Alice.blindCredentialY();


        //Get private key and create cipher text, print out to prove it works Temporary method
        PrivateKey privateKey = ibe.extract(Alice.getEmail());
        CipherTextTuple c = Bob.sendMessage(Alice.getEmail(), ibe);

        ibe.decrypt(privateKey, c).ifPresent(System.out::println);

    }
}
