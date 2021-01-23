/** 
 * Copyright (c) 1998, 2019, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.zul.aes;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.zul.aes"),
	    @StringDef(name = "AppletName", value = "Zullet")},
	    // Insert your strings here 
	name = "ZulletStrings")
public class Zullet extends Applet {
	
	private static final byte INS_AES_ENC_DEC = (byte)0x55;
	private static final byte INS_AES_CHG_KEY = (byte)0x23;
	private static final byte INS_AES_CHG_ICV = (byte)0x78;
	
	private byte[] key = {(byte)0x70, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x77, (byte)0x6F, (byte)0x72, (byte)0x64, (byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38};
	private byte[] iv = {(byte)0x76, (byte)0x65, (byte)0x72, (byte)0x79, (byte)0x73, (byte)0x65, (byte)0x63, (byte)0x72, (byte)0x65, (byte)0x74, (byte)0x61, (byte)0x65, (byte)0x73, (byte)0x69, (byte)0x76, (byte)0x63};
	
	private Cipher aesCipher;
	private AESKey aesKey;
	
	private boolean init;
	
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Zullet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected Zullet() {
    	aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    	aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    	init = false;
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
        //Insert your code here
    	if(selectingApplet())
    		return;
    	
    	byte[] buf = apdu.getBuffer();
    	short len = apdu.setIncomingAndReceive();
    	
    	switch(buf[ISO7816.OFFSET_INS]) {
    		case INS_AES_CHG_KEY:
    			chgKey(apdu, len);
    			break;
    		case INS_AES_CHG_ICV:
    			chgIv(apdu, len);
    			break;
    		case INS_AES_ENC_DEC:
    			encryptDecrypt(apdu, len);
    			break;
    		default:
    			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    	}
    }
    
    private void chgIv(APDU apdu, short len) {
    	if(len != 16)
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, iv, (short)0, (short)16);
    }
    
    private void chgKey(APDU apdu, short len) {
    	if(len != 16)
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, key, (short)0, (short)16);
    }
    
    private void encryptDecrypt(APDU apdu, short len) {
    	
    	if (len <= 0 || len % 16 != 0)
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	
    	byte[] buffer = apdu.getBuffer();
    	
    	boolean hasMoreCmd = (buffer[ISO7816.OFFSET_P2] != (byte)0x00);
    	
    	byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
    	
    	if(!init) {
    		aesKey.setKey(key, (short) 0);
        	aesCipher.init(aesKey, mode, iv, (short)0, (short)16);
        	init = true;
    	}
    	
    	if(hasMoreCmd) {
    		aesCipher.update(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
    	}else {
    		aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
    		init = false;
    	}
    	
    	apdu.setOutgoingAndSend((short)0, len);
    }
    
}
