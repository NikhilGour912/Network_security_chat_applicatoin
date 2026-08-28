#include <iostream>
#include <string>
#include <thread>

#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

const int PORT = 5000;

// Receive messages from server
void receive_messages(int socket_fd)
{
    char buffer[1024];

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));

        int bytes_received = recv(
            socket_fd,
            buffer,
            sizeof(buffer) - 1,
            0);

        if (bytes_received <= 0)
        {
            cout << "\n[Client] Server disconnected."
                 << endl;

            break;
        }

        cout << "\n[Message] "
             << string(buffer, bytes_received);

        cout << "> ";
        cout.flush();
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        cout << "Usage: ./client <server-ip>" << endl;
        return 1;
    }

    string server_ip = argv[1];

    // Create TCP socket
    int client_socket = socket(
        AF_INET,
        SOCK_STREAM,
        0);

    if (client_socket < 0)
    {
        perror("socket");
        return 1;
    }

    // Server address
    sockaddr_in server_address{};

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    if (inet_pton(
            AF_INET,
            server_ip.c_str(),
            &server_address.sin_addr) <= 0)
    {
        cout << "Invalid server IP address."
             << endl;

        close(client_socket);
        return 1;
    }

    // Connect
    if (connect(
            client_socket,
            (sockaddr *)&server_address,
            sizeof(server_address)) < 0)
    {
        perror("connect");
        close(client_socket);
        return 1;
    }

    cout << "==================================" << endl;
    cout << "      Secure Chat - Phase 1       " << endl;
    cout << "==================================" << endl;

    cout << "Connected to server "
         << server_ip
         << ":"
         << PORT
         << endl;

    cout << "Type messages below." << endl;

    // Thread for receiving messages
    thread receiver(
        receive_messages,
        client_socket);

    receiver.detach();

    // Send messages
    string message;

    while (true)
    {
        cout << "> ";
        getline(cin, message);

        if (cin.eof())
            break;

        if (message.empty())
            continue;

        // Send message
        string data = message + "\n";

        int bytes_sent = send(
            client_socket,
            data.c_str(),
            data.size(),
            0);

        if (bytes_sent < 0)
        {
            perror("send");
            break;
        }
    }

    close(client_socket);

    return 0;
}