package com.zul.client;

import com.sun.javacard.apduio.Apdu;

public interface IConnection {
	abstract void connect() throws Exception;
	abstract void close() throws Exception;
	
	abstract Apdu transmit(byte[] data) throws Exception;
}
