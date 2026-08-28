#include <iostream>
#include <string>
#include <thread>
#include <mutex>

#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

const int PORT = 5000;
const int MAX_CLIENTS = 2;

int clients[MAX_CLIENTS] = {-1, -1};

mutex clients_mutex;

// Send a complete message to a client
void send_message(int socket_fd, const string &message)
{
    string data = message + "\n";

    send(socket_fd, data.c_str(), data.size(), 0);
}

// Handle one connected client
void handle_client(int client_socket, int client_id)
{
    char buffer[1024];

    cout << "[Server] Client " << client_id << " connected." << endl;

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));

        int bytes_received = recv(
            client_socket,
            buffer,
            sizeof(buffer) - 1,
            0);

        if (bytes_received <= 0)
        {
            cout << "[Server] Client "
                 << client_id
                 << " disconnected."
                 << endl;

            close(client_socket);

            lock_guard<mutex> lock(clients_mutex);
            clients[client_id] = -1;

            break;
        }

        string message(buffer, bytes_received);

        // Remove trailing newline if present
        while (!message.empty() &&
               (message.back() == '\n' || message.back() == '\r'))
        {
            message.pop_back();
        }

        // Server can see the complete plaintext message
        cout << "[Server] Received from Client "
             << client_id
             << ": "
             << message
             << endl;

        // Find the other client
        int other_client = (client_id == 0) ? 1 : 0;

        lock_guard<mutex> lock(clients_mutex);

        if (clients[other_client] != -1)
        {
            send_message(
                clients[other_client],
                message);

            cout << "[Server] Relayed: "
                 << message
                 << endl;
        }
    }
}

int main()
{
    // Create TCP socket
    int server_socket = socket(
        AF_INET,
        SOCK_STREAM,
        0);

    if (server_socket < 0)
    {
        perror("socket");
        return 1;
    }

    // Allow quick restart of server
    int opt = 1;

    setsockopt(
        server_socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt));

    // Server address
    sockaddr_in server_address{};

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    // Bind
    if (bind(
            server_socket,
            (sockaddr *)&server_address,
            sizeof(server_address)) < 0)
    {
        perror("bind");
        close(server_socket);
        return 1;
    }

    // Listen
    if (listen(server_socket, MAX_CLIENTS) < 0)
    {
        perror("listen");
        close(server_socket);
        return 1;
    }

    cout << "==================================" << endl;
    cout << "      Secure Chat - Phase 1       " << endl;
    cout << "==================================" << endl;

    cout << "[Server] Listening on port "
         << PORT
         << endl;

    // Accept exactly two clients
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        sockaddr_in client_address{};
        socklen_t client_length = sizeof(client_address);

        int client_socket = accept(
            server_socket,
            (sockaddr *)&client_address,
            &client_length);

        if (client_socket < 0)
        {
            perror("accept");
            continue;
        }

        {
            lock_guard<mutex> lock(clients_mutex);
            clients[i] = client_socket;
        }

        cout << "[Server] Client "
             << i
             << " accepted from "
             << inet_ntoa(client_address.sin_addr)
             << endl;

        // Handle client independently
        thread(
            handle_client,
            client_socket,
            i)
            .detach();
    }

    cout << "[Server] Two clients connected." << endl;

    // Keep server alive
    while (true)
    {
        sleep(1);
    }

    close(server_socket);

    return 0;
}