package fit.wenchao.crypto_tools;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.math.ec.*;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author ccm
 */
public class Sm2Signer implements ECConstants, Sm2Constants {

    private Sm2Signer(){}

    public static Sm2Signer INSTANCE = new Sm2Signer();

    private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
    private ECDomainParameters ecParams;
    private ECKeyParameters ecKey;
    private final DSAEncoding encoding = StandardDSAEncoding.INSTANCE;

    public byte[] signDsa(byte[] eHash, byte[] privateKey) {
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey),
                DOMAIN_PARAMS);
        return signDsa(eHash, privateKeyParameters);
    }

    private byte[] signDsa(byte[] eHash, CipherParameters param) {
        ecKey = (ECKeyParameters) param;
        ecParams = ecKey.getParameters();
        kCalculator.init(ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
        BigInteger n = ecParams.getN();
        BigInteger e = calculateE(n, eHash);
        BigInteger d = ((ECPrivateKeyParameters) ecKey).getD();
        BigInteger r, s;
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                // A3
                k = kCalculator.nextK();

                // A4
                ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

                // A5
                r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
            } while (r.equals(ZERO) || r.add(k).equals(n));

            // A6
            BigInteger dPlus1ModN = d.add(ONE).modInverse(n);

            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        } while (s.equals(ZERO));

        // A7
        try {
            return encoding.encode(ecParams.getN(), r, s);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public boolean verifyDsa(byte[] eHash, byte[] signature, byte[] publicKey) {
        ECPublicKeyParameters ecPublicKeyParameters = Sm2Util.buildEcPublicKeyParameters(publicKey);
        return verifyDsa(eHash, signature, ecPublicKeyParameters);
    }

    private boolean verifyDsa(byte[] eHash, byte[] signature, CipherParameters param) {
        ecKey = (ECKeyParameters) param;
        ecParams = ecKey.getParameters();
        try {
            BigInteger[] rs = encoding.decode(ecParams.getN(), signature);

            BigInteger r = rs[0];
            BigInteger s = rs[1];
            BigInteger n = ecParams.getN();
            // B1
            if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0) {
                return false;
            }
            // B2
            if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0) {
                return false;
            }
            // B4
            BigInteger e = calculateE(n, eHash);

            // B5
            BigInteger t = r.add(s).mod(n);
            if (t.equals(ZERO)) {
                return false;
            }
            // B6
            ECPoint q = ((ECPublicKeyParameters) ecKey).getQ();
            ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(ecParams.getG(), s, q, t).normalize();
            if (x1y1.isInfinity()) {
                return false;
            }
            // B7
            BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);
            return expectedR.equals(r);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    protected BigInteger calculateE(BigInteger n, byte[] message) {
        return new BigInteger(1, message);
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
