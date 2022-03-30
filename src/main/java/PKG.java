import cryptid.CryptID;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.SecurityLevel;
import cryptid.ibe.exception.SetupException;

import javax.swing.plaf.SeparatorUI;
import java.io.PipedReader;

//Public wrapper class
public class PKG {

    //IBE instance used for application
    private IdentityBasedEncryption ibe;

    //Public constructor
    public PKG() throws SetupException{
        ibe = CryptID.setupBonehFranklin(SecurityLevel.LOWEST);
    }

    //Return IBE instance
    public IdentityBasedEncryption getInstance(){
        return ibe;
    }

    //Current empty method for decryption
    public PrivateKey getPrivateKey(){

        return ibe.extract("test");
    }
}
