import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;

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

        System.out.println("~~ Setup ~~");
        //Create PKG/IBE wrapper class for issuing private keys
        System.out.println("Creating PKG...");

        PKGWrapper pkgWrapper = new PKGWrapper();
        //Get instance of IBE in wrapper class for use in encrypting
        IdentityBasedEncryption ibe = pkgWrapper.getInstance();

        System.out.println("Creating CA...");
        CA certificateAuthority = new CA(ibe.getPublicParameters());
        Utilities.setSystemParameters(certificateAuthority);

        //Create Bob and Alice and receive their credentials
        System.out.println("Creating Bob (sender)...");
        Client Bob = new Client("bob@gmail.com");
        System.out.println("Issuing digital credential for Bob");
        Bob.requestCredential(certificateAuthority);


        System.out.println("Creating Alice (receiver)...");
        Client Alice = new Client("alice@gmail.com");
        System.out.println("Issuing digital credential for Alice");
        Alice.requestCredential(certificateAuthority);
        System.out.println("~~ Setup Completed ~~\n");

        System.out.println("Bob sends an encrypted message to Alice...");
        System.out.println("Bob uses Alice's point P(x,y) as the Public Key");
        String alice_ec_public_key = Alice.get_x() + Alice.get_y();
        CipherTextTuple cipher = Bob.sendMessage(alice_ec_public_key,ibe);

        //Get blinded credentials
        System.out.println("Blinding Alice's Credentials...\n");
        System.out.println("Creating blinded credential C_x");
        Credential blinded_cx =Alice.blindCredentialX();
        System.out.println("Created blinded credential C_y\n");
        Credential blinded_cy = Alice.blindCredentialY();

        //show and verify credentials
        System.out.println("Showing blinded credential C_x");
        Alice.showBlindedCredentialsToPKG(pkgWrapper, blinded_cx );
        System.out.println("Showing blinded credential C_y");
        Alice.showBlindedCredentialsToPKG(pkgWrapper, blinded_cy);
        String alice_blinded_ec_public_key = Alice.get_blinded_x() + Alice.get_blinded_y();
        //after verification, pkg must compute blinded private key k'
        System.out.println("PKG issuing (blinded) private key...");
        //System.out.println(blinded_xy_coord);
        PrivateKey blinded_pk = ibe.extract(alice_blinded_ec_public_key);


        System.out.println("Alice unblinds private key...");
        PrivateKey unblinded_pk = Alice.unblind_private_key(blinded_pk, certificateAuthority);

        System.out.println("Alice now decrypts the message...");
        ibe.decrypt(unblinded_pk, cipher).ifPresent(System.out::println);

    }
}
