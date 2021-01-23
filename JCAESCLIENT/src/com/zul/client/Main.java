package com.zul.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

import com.sun.javacard.apduio.Apdu;

public class Main {
	
	private static final byte CLA = (byte)0x80;
	private static final byte AES_INS = (byte)0x55;
	private static final byte KEY_INS = (byte)0x23;
	private static final byte ICV_INS = (byte)0x78;
	private static final byte ENC_P1 = (byte)0x00;
	private static final byte DEC_P1 = (byte)0x01;
	private static final byte UPD_P2 = (byte)0x01;
	private static final byte FIN_P2 = (byte)0x00;
	
	public static byte[] pad(byte[] buf) {
		
		int blocks = buf.length/16;
		byte[] newBuf = new byte[(blocks + 1)*16];
		
		int a = buf.length % 16;
		int b = buf.length / 16;
		int padding = 16 - a;
		
		for(int i=0; i<buf.length; i++)
			newBuf[i] = buf[i];
		
		System.out.println("Padding input with value: " + padding);
		
		for(int i=0; i<padding; i++)
			newBuf[b*16+a+i] = (byte) padding;
		
		return newBuf;
	}
	
	public static byte[] rmPad(byte[] buf) {
		
		int padding = buf[buf.length-1];
		
		System.out.println("Discovered padding with value: " + padding);
		System.out.println("Removing...");
		
		byte[] newBuf = new byte[buf.length-padding];
		
		for(int i=0; i<newBuf.length; i++)
			newBuf[i] = buf[i];
		
		return newBuf;
	}
	
	public static void encryptDecrypt(String inFile, IConnection c, boolean encrypt, String outFile) throws Exception {
		
		System.out.println("-----");
		
		if(encrypt)
			System.out.println("Encryption");
		else
			System.out.println("Decryption");
		
		byte[] buf = Files.readAllBytes(Paths.get(inFile));
		if(buf==null)
			throw new Exception("Input file not found!");
		System.out.println("Read " + buf.length + " bytes from the input file " + inFile);
		File output = new File(outFile);
		if(!output.exists())
			output.createNewFile();
		FileOutputStream fos = new FileOutputStream(output);
		
		if(encrypt)
			buf = pad(buf);
		
		byte[] challenge = new byte[21];
		byte[] data = new byte[16];
		
		challenge[0] = CLA;
		challenge[1] = AES_INS;
		challenge[2] = encrypt ? ENC_P1 : DEC_P1;
		challenge[3] = UPD_P2;
		challenge[4] = (byte)0x10;
		
		if(encrypt)
			System.out.println("Starting encryption operation");
		else
			System.out.println("Starting decryption operation");
		
		for(int i=0; i<buf.length/16; i++) {
			if(i == buf.length/16-1)
				challenge[3] = FIN_P2;
			for(int j=0; j<16; j++)
				data[j] = buf[i*16+j];
			System.arraycopy(data, 0, challenge, 5, data.length);
			Apdu apdu = c.transmit(challenge);
			if(!encrypt && i == buf.length/16-1) {
				byte[] temp = rmPad(apdu.getDataOut());
				fos.write(temp);
			}
			else
				fos.write(apdu.getDataOut());
		}
		
		if(encrypt)
			System.out.println("Encryption process finished!");
		else
			System.out.println("Decryption process finished!");
		
		fos.close();
		System.out.println("Wrote to file " + outFile);
		
		System.out.println("-----");
	}
	
	public static void chgKey(String pass, IConnection c) throws Exception {
		System.out.println("-----");
		byte[] command = new byte[21];
		command[0] = CLA;
		command[1] = KEY_INS;
		command[2] = (byte)0x00;
		command[3] = (byte)0x00;
		command[4] = (byte)0x10;
		if(pass.length()==16) {
			System.out.println("Changing key to " + pass);
			for(int i=0;i<pass.length();i++)
				command[5+i]=pass.getBytes()[i];
			c.transmit(command);
			System.out.println("Key changed!");
		}
		else
			System.out.println("Invalid key length!");
		System.out.println("-----");
	}
	
	public static void chgIv(String ivc, IConnection c) throws Exception {
		System.out.println("-----");
		byte[] command = new byte[21];
		command[0] = CLA;
		command[1] = ICV_INS;
		command[2] = (byte)0x00;
		command[3] = (byte)0x00;
		command[4] = (byte)0x10;
		if(ivc.length()==16) {
			System.out.println("Changing IV to " + ivc);
			for(int i=0;i<ivc.length();i++)
				command[5+i]=ivc.getBytes()[i];
			c.transmit(command);
			System.out.println("IV changed!");
		}
		else
			System.out.println("Invalid IV length!");
		System.out.println("-----");
	}
	
	public static void main(String[] args) throws Exception {
		
		IConnection c;
		c = new Connection();
		c.connect();
		
		FileInputStream fis = new FileInputStream("jcardcheat.txt");
		Scanner sc = new Scanner(fis);
		
		try {
			
			while(sc.hasNextLine()) {
				String[] tokens = sc.nextLine().replace("0x", "").replace(";", "").replace("powerup", "").split(" ");
				if(tokens[0].length()==0 || tokens[0].startsWith("//"))
					continue;
				byte[] data = new byte[tokens.length-1];
				for(int i=0; i<tokens.length-1; i++)
					data[i] = (byte)Integer.parseInt(tokens[i], 16);
				c.transmit(data);
			}
			
			//default key: password12345678
			//default iv: verysecretaesicv
			
			chgKey("Password12345!@7", c); //optional to set these up
			chgIv("StudentIsm@ASE#_", c); //optional to set these up
			
			encryptDecrypt("msg.txt", c, true, "enc.dat");
			encryptDecrypt("enc.dat", c, false, "dec.txt");
			
		} catch(Exception e) {
			throw e;
		} finally {
			c.close();
			sc.close();
		}
		
	}

}
