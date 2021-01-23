package com.zul.client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.net.Socket;
import com.sun.javacard.apduio.*;

public class Connection implements IConnection {
	
	private CadClientInterface cad;
	private Socket sock;
	private int port;
	
	public Connection() {
		port = 9025;
	}
	
	public void connect() throws Exception {
		System.out.println("Attempting to connect...");
		sock = new Socket("localhost", port);
		sock.setTcpNoDelay(true);
		BufferedInputStream is = new BufferedInputStream(sock.getInputStream());
		BufferedOutputStream os = new BufferedOutputStream(sock.getOutputStream());
		cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
		cad.powerUp();
		System.out.println("Connection successful!");
	}

	public void close() throws Exception {
		System.out.println("Ending connection...");
		cad.powerDown();
		sock.close();
		cad = null;
		System.out.println("Connection ended!");
	}

	public Apdu transmit(byte[] data) throws Exception {
		Apdu a = new Apdu(data);
		cad.exchangeApdu(a);
		return a;
	}

}
