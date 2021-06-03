package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;

public class Client {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private EncryptionAES encryptionAES;

    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            waitForPartner();
            long sharedKey = getSharedKeyWithDH();
            encryptionAES = new EncryptionAES(sharedKey + "");
            initializeReceivingMessages();
            initializeKeyboard();
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            stopConnection();
        }
    }

    private void initializeKeyboard() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Channel is secure and ready for message transfer...");
        System.out.println("Type 'exit' to stop the program");
        while (true) {
            System.out.print("$ ");
            String message = scanner.nextLine();
            if ("exit".equalsIgnoreCase(message))
                break;
            out.println(encryptionAES.encrypt(message));
        }
    }

    private void initializeReceivingMessages() {
        new Thread(() -> {
            while (true) {
                try {
                    String receivedMessage = in.readLine();
                    System.out.println("\nEncrypted Message from partner : " + receivedMessage);
                    String decrypted = encryptionAES.decrypt(receivedMessage);
                    System.out.println("Decrypted Message from partner : " + decrypted);
                } catch (IOException e) {
                    stopConnection();
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void waitForPartner() throws IOException {
        while (true) {
            String input = in.readLine();
            if (input.equals("ready")) {
                System.out.println("your partner has joined the channel...");
                break;
            }
            System.out.println(input);
        }
    }

    public long getPartnersPublicKey() throws IOException {
        while (true) {
            String received = in.readLine();
            try {
                return Long.parseLong(received);
            } catch (Exception e) {
            }
        }
    }

    public long getSharedKeyWithDH() throws IOException {
        long privatKey = generatePrivateKey();
        long publicKey = getPublicKey(privatKey);
        System.out.println("Sending " + publicKey + " to your partner");
        out.println(publicKey);
        long partnerPublicKey = getPartnersPublicKey();
        System.out.println("Partner's Public Key : " + partnerPublicKey);
        System.out.println("Diffie-Hellman key exchange completed!");
        return (long) Math.pow(partnerPublicKey, privatKey) % 23;
    }

    private long getPublicKey(long privatKey) {
        return (long) Math.pow(9, privatKey) % 23;
    }

    private long generatePrivateKey() {
        Random random = new Random();
        return random.nextInt(10 + 1) + 1;
    }


    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
