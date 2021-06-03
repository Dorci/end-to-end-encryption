package server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
    private ServerSocket serverSocket;
    private ClientHandler clientOne;
    private ClientHandler clientTwo;

    public void start(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        System.out.println("Welcome to partial E2EE");
        System.out.println("Waiting for communication Partner to join...");
        clientOne = new ClientHandler(serverSocket.accept(), "Jupiter");
        clientOne.start();
        clientTwo = new ClientHandler(serverSocket.accept(), "Klepner");
        clientTwo.start();
        clientOne.setPartner(clientTwo);
        clientTwo.setPartner(clientOne);
    }

    public void stop() throws IOException {
        serverSocket.close();
    }

}
