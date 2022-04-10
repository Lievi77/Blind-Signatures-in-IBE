import cryptid.ellipticcurve.point.affine.AffinePoint;
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
        System.out.println("\nCreating Bob (sender)...");
        Client Bob = new Client("bob@gmail.com");
        System.out.println("Issuing digital credential for Bob");
        Bob.requestCredential(certificateAuthority);


        System.out.println("\nCreating Alice (receiver)...");
        Client Alice = new Client("alice@gmail.com");
        System.out.println("Issuing digital credential for Alice");
        Alice.requestCredential(certificateAuthority);
        System.out.println("~~ Setup Completed ~~\n");

        System.out.println("Bob sends an encrypted message to Alice...");
        AffinePoint alice_ec_public_key = Alice.get_user_point();
        String message = "Honors Project 2022 Rocks";
        System.out.println("Message to be sent: " + message);
        CipherTextTuple cipher = Bob.sendMessage(alice_ec_public_key,ibe, message);

        //Get blinded credentials
        System.out.println("\nBlinding Alice's Credentials...");
        System.out.println("Creating blinded credential C_x");
        Credential blinded_cx =Alice.blindCredentialX();
        System.out.println("Created blinded credential C_y\n");
        Credential blinded_cy = Alice.blindCredentialY();

        //show and verify credentials
        System.out.println("Showing blinded credential C_x");
        Alice.showBlindedCredentialsToPKG(pkgWrapper, blinded_cx );
        System.out.println("Showing blinded credential C_y");
        Alice.showBlindedCredentialsToPKG(pkgWrapper, blinded_cy);

       AffinePoint alice_blinded_ec_public_key = Alice.get_user_blinded_point();
        System.out.println("Blinded EC Point shown to PKG: " +alice_blinded_ec_public_key);
        //after verification, pkg must compute blinded private key k'
        System.out.println("\nPKG issuing (blinded) private key...");
        PrivateKey blinded_pk = ibe.extract(alice_blinded_ec_public_key);


        System.out.println("Alice unblinds private key...");
        PrivateKey unblinded_pk = Alice.unblind_private_key(blinded_pk);

       PrivateKey pk = ibe.extract(alice_ec_public_key);
        assert pk.equals(unblinded_pk ): "Unblinded pk should equal pk";

        System.out.println("\nAlice now decrypts the message...");
        System.out.println("Message is:");
        ibe.decrypt(unblinded_pk, cipher).ifPresent(System.out::println);

    }
}
