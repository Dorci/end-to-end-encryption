package client;

public class ClientMain {
    public static void main(String[] args) {
        new Client().startConnection("127.0.0.1", 1234);
    }
}
