package com.mtlogic.security;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * This is a simple example of how to create and verify digital signatures with Java. 
 * The example also demonstrates basic base64 encoding/decoding techniques.
 * 
 * @author Mike Trentman
 *
 */
public class SignatureVerification 
{
	public static void main (String[] args) throws Exception 
	{
	    // check args and get plaintext
	    if (args.length !=1) 
	    {
	    	System.err.println("Usage: java DigitalSignature1Example text");
	    	System.exit(1);
	    }
	    byte[] plainText = args[0].getBytes("UTF8");
	    //
	    // generate an RSA keypair
	    System.out.println( "\nStart generating RSA key" );
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);

	    KeyPair key = keyGen.generateKeyPair();
	    System.out.println( "Finish generating RSA key" );
	    //
	    // get a signature object using the MD5 and RSA combo
	    // and sign the plaintext with the private key,
	    // listing the provider along the way
	    Signature sig = Signature.getInstance("MD5WithRSA");
	    sig.initSign(key.getPrivate());
	    sig.update(plainText);
	    byte[] signature = sig.sign();
	    System.out.println( sig.getProvider().getInfo() );
	    System.out.println( "\nSignature:" );
	    System.out.println( new String(signature, "UTF8") );
	    
	    // Let's encode the Signature in Base64
	    // This could be useful for instance if sending this signature as a string
	    // perhaps in an XML document
	    BASE64Encoder encoder = new BASE64Encoder();
	    String base64EncodedSignature = encoder.encode(signature); // Encode
	    System.out.println( "\nSignature (Encoded in base64): ");
	    System.out.println(base64EncodedSignature);
	    
	    BASE64Decoder decoder = new BASE64Decoder();
	    byte[] decodedSignatureBytes = decoder.decodeBuffer(base64EncodedSignature); // Decode
	    System.out.println( "\nSignature (After decoding from base64): ");
	    System.out.println(new String(decodedSignatureBytes, "UTF8"));
	    
	    // verify the signature with the public key
	    System.out.println( "\nStart signature verification" );
	    sig.initVerify(key.getPublic());
	    sig.update(plainText);
	    try
	    {
	    	if (sig.verify(decodedSignatureBytes)) 
	    	{
	    		System.out.println( "Signature verified" );
	    	} 
	    	else 
	    	{
	    		System.out.println( "Signature failed" );
	    	}
	    } 
	    catch (SignatureException se) 
	    {
	    	System.out.println( "Signature failed" );
	    }
	}
}