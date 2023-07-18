package fit.wenchao.crypto_tools;

import lombok.Data;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author ccm
 * @version V1.0
 * @Package com.ccm.sm.soft.sm2
 * @date 2020/8/26 3:56 下午
 * @Copyright © 2020-2021 ccm
 */
@Data
public class Sm2Cipher {
    /**
     * 椭圆曲线点 64字节
     */
    private byte[] c1;
    /**
     * 密文数据 与明文同长
     */
    private byte[] c2;
    /**
     * SM3的摘要值 32字节
     */
    private byte[] c3;

    public static byte[] toByte(Sm2Cipher cipher, SM2Engine.Mode mode) {
        byte[] header = {0x04};
        if (mode == SM2Engine.Mode.C1C3C2) {
            return Arrays.concatenate(header, cipher.c1, cipher.c3, cipher.c2);
        }
        return Arrays.concatenate(header, cipher.c1, cipher.c2, cipher.c3);
    }

    public static byte[] toByte(Sm2Cipher sm2Cipher) {
        return toByte(sm2Cipher, SM2Engine.Mode.C1C2C3);
    }

    public static Sm2Cipher fromByte(byte[] cipher, SM2Engine.Mode mode) {
        cipher = Arrays.copyOfRange(cipher, 1, cipher.length);
        Sm2Cipher sm2Cipher = new Sm2Cipher();
        sm2Cipher.setC1(Arrays.copyOfRange(cipher, 0, 64));
        if (mode == SM2Engine.Mode.C1C3C2) {
            sm2Cipher.setC3(Arrays.copyOfRange(cipher, 64, 96));
            sm2Cipher.setC2(Arrays.copyOfRange(cipher, 96, cipher.length));
        } else {
            sm2Cipher.setC2(Arrays.copyOfRange(cipher, 64, cipher.length - 32));
            sm2Cipher.setC3(Arrays.copyOfRange(cipher, cipher.length - 32, cipher.length));
        }
        return sm2Cipher;
    }

    public static Sm2Cipher fromByte(byte[] cipher) {
        return fromByte(cipher, SM2Engine.Mode.C1C2C3);
    }

    public static byte[] to300Byte(Sm2Cipher cipher) {
        byte[] r = new byte[300];
        System.arraycopy(cipher.c1, 0, r, 32, 32);
        System.arraycopy(cipher.c1, 32, r, 96, 32);
        System.arraycopy(cipher.c3, 0, r, 128, cipher.c3.length);
        byte[] length = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(cipher.c2.length).array();
        System.arraycopy(length, 0, r, 160, 4);
        System.arraycopy(cipher.c2, 0, r, 164, cipher.c2.length);
        return r;
    }

    public static Sm2Cipher from300Byte(byte[] data) {
        Sm2Cipher sm2Cipher = new Sm2Cipher();
        byte[] x = Arrays.copyOfRange(data, 32, 64);
        byte[] y = Arrays.copyOfRange(data, 96, 128);
        sm2Cipher.setC1(ByteUtils.concatenate(x, y));
        sm2Cipher.setC3(Arrays.copyOfRange(data, 128, 160));
        int length = ByteBuffer.wrap(Arrays.copyOfRange(data, 160, 164)).order(ByteOrder.LITTLE_ENDIAN).getInt();
        sm2Cipher.setC2(Arrays.copyOfRange(data, 164, 164 + length));
        return sm2Cipher;
    }
}
