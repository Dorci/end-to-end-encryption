package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientHandler extends Thread {
    private final Socket clientSocket;
    private final PrintWriter out;
    private final BufferedReader in;
    private final String name;
    private ClientHandler partner;


    public ClientHandler(Socket socket, String name) throws IOException {
        this.clientSocket = socket;
        this.out = new PrintWriter(socket.getOutputStream(), true);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.name = name;
    }

    @Override
    public void run() {
        try {
            waitForPartner();
            forwardMessages();
            closeConnection();
        } catch (Exception e) {

        }
    }

    private void waitForPartner() throws InterruptedException {
        while (partner == null) {
            sendMessageToClient("Waiting for partner...");
            Thread.sleep(2000);
        }
        sendMessageToClient("ready");
    }

    private void forwardMessages() throws IOException {
        String inputLine;
        while ((inputLine = getNextPartnerMessage()) != null) {
            if ("exit".equals(inputLine)) {
                sendMessageToPartner("bye");
                break;
            }
            System.out.println("Server-Middle-Man : "+inputLine);
            sendMessageToClient(inputLine);
        }
    }

    private String getNextPartnerMessage() throws IOException {
        return partner.getIn().readLine();
    }

    private void sendMessageToPartner(String text) {
        partner.sendMessageToClient(text);
    }

    private void closeConnection() throws IOException {
        in.close();
        out.close();
        clientSocket.close();
    }

    public void sentToBoth(String text) {
        sendMessageToClient(text);
        partner.sendMessageToClient(text);
    }

    public void sendMessageToClient(String text) {
        out.println(text);
    }

    public void setPartner(ClientHandler clientHandler) {
        this.partner = clientHandler;
    }

    public String getClientName() {
        return name;
    }

    public PrintWriter getOut() {
        return out;
    }

    public BufferedReader getIn() {
        return in;
    }
}
