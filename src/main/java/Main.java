import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.PublicParameters;

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

        PKG pkg = new PKG();
        //Get instance of IBE in wrapper class for use in encrypting
        IdentityBasedEncryption ibe = pkg.getInstance();

        System.out.println("Creating CA...");
        CA certificateAuthority = new CA();
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

        System.out.println("Bob sends an encrypted message to Alice...");
        String ec_public_key = Alice.get_x() + Alice.get_y();
        CipherTextTuple cipher = Bob.sendMessage(ec_public_key,ibe);

        //Get blinded credentials
        System.out.println("Blinding Alice's Credentials...\n");
        System.out.println("Creating blinded credential C_x");
        Credential blinded_cx =Alice.blindCredentialX();
        System.out.println("Created blinded credential C_y\n");
        Credential blinded_cy = Alice.blindCredentialY();

        //show and verify credentials
        System.out.println("Showing blinded credential C_x");
        Alice.showBlindedCredentialsToPKG(pkg, blinded_cx );
        System.out.println("Showing blinded credential C_y");
        Alice.showBlindedCredentialsToPKG(pkg, blinded_cy);
        String blinded_xy_coord = Alice.get_blinded_x() + Alice.get_blinded_y();
        //after verification, pkg must compute blinded private key k'
        System.out.println("PKG issuing (blinded) private key...");
        //System.out.println(blinded_xy_coord);
        PrivateKey blinded_pk = ibe.extract(blinded_xy_coord);


        System.out.println("Alice unblinds private key...");
        PrivateKey unblinded_pk = Alice.unblind_private_key(blinded_pk, certificateAuthority);

        System.out.println("Alice now decrypts the message...");
        ibe.decrypt(unblinded_pk, cipher).ifPresent(System.out::println);

    }
}
