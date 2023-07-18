package fit.wenchao.crypto_tools;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author ccm
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Sm2Signature {
    private static final int LENGTH = 32;

    private byte[] r;
    private byte[] s;

    /**
     * 将结构体转化成64字节纯数据
     *
     * @param sm2Signature 结构体
     * @return 二进制
     */
    public static byte[] toByte(Sm2Signature sm2Signature) {
        return ByteUtils.concatenate(sm2Signature.getR(), sm2Signature.getS());
    }

    /**
     * 将结构体转化成dsa数据
     *
     * @param sm2Signature 结构体
     * @param dsaEncoding encoding
     * @return 二进制
     */
    public static byte[] toDsa(Sm2Signature sm2Signature, DSAEncoding dsaEncoding) {
        BigInteger bigIntegerSignR = new BigInteger(Hex.toHexString(sm2Signature.getR()), 16);
        BigInteger bigIntegerSignS = new BigInteger(Hex.toHexString(sm2Signature.getS()), 16);
        byte[] dsa = null;
        try {
            dsa = dsaEncoding.encode(Sm2Constants.SM2_ECC_N, bigIntegerSignR, bigIntegerSignS);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dsa;
    }

    /**
     * 纯数据转化成dsa
     *
     * @param bytes 二进制
     * @param dsaEncoding encoding
     * @return 二进制
     */
    public static byte[] byteToDsa(byte[] bytes, DSAEncoding dsaEncoding) {
        return toDsa(fromByte(bytes), dsaEncoding);
    }

    /**
     * 从64字节数据得到结构体
     *
     * @param sign sign
     * @return Sm2Signature
     */
    public static Sm2Signature fromByte(byte[] sign) {
        Sm2Signature sm2Signature = new Sm2Signature();
        sm2Signature.setR(Arrays.copyOf(sign, LENGTH));
        sm2Signature.setS(Arrays.copyOfRange(sign, LENGTH, sign.length));
        return sm2Signature;
    }

    /**
     * 从Dsa转化获取结构体
     *
     * @param dsa dsa
     * @param dsaEncoding dsaEncoding
     * @return Sm2Signature
     */
    public static Sm2Signature fromDsa(byte[] dsa, DSAEncoding dsaEncoding) {
        Sm2Signature sm2Signature = new Sm2Signature();
        try {
            BigInteger[] bigIntegers = dsaEncoding.decode(Sm2Constants.SM2_ECC_N, dsa);
            sm2Signature.r = bigIntegers[0].toByteArray();
            if (sm2Signature.r.length > LENGTH) {
                sm2Signature.r = Arrays.copyOfRange(sm2Signature.r, 1, sm2Signature.r.length);
            }
            sm2Signature.s = bigIntegers[1].toByteArray();
            if (sm2Signature.s.length > LENGTH) {
                sm2Signature.s = Arrays.copyOfRange(sm2Signature.s, 1, sm2Signature.s.length);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sm2Signature;
    }

}
