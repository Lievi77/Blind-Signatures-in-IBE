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
        String message = "Honors Project 2022";
        CipherTextTuple cipher = Bob.sendMessage(alice_ec_public_key,ibe, message);

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
        System.out.println(alice_blinded_ec_public_key);
        //after verification, pkg must compute blinded private key k'
        System.out.println("\nPKG issuing (blinded) private key...");
        PrivateKey blinded_pk = ibe.extract(alice_blinded_ec_public_key);


        System.out.println("Alice unblinds private key...");
        PrivateKey unblinded_pk = Alice.unblind_private_key(blinded_pk);

       PrivateKey pk = ibe.extract(alice_ec_public_key);
        System.out.println("Actual Key: " + pk.getData());
        System.out.println("Unblinded Key: " + unblinded_pk.getData());
        assert pk.equals(unblinded_pk ): "Unblinded pk should equal pk";

        System.out.println("Alice now decrypts the message...\n");
        System.out.println("Message is: ");
        ibe.decrypt(unblinded_pk, cipher).ifPresent(System.out::println);

       // Utilities.get_generator(161);
    }
}
