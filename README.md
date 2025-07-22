# ZCDNS Tunnel

**Stateless SSH Port Forwarding via DNS**

This project provides a stateless, dynamic SSH port forwarding solution that allows you to expose local services to the internet using custom domains. Authentication and authorization are handled entirely through DNS records, eliminating the need for a server-side database.

## How It Works

1.  **DNS Setup:**
    *   Create a CNAME record for your custom domain (e.g., `your-domain.com`) that points to the tunnel server's domain (e.g., `server.tunnellku.net`).
    *   Add a TXT record to your domain with your SSH public key:

        ```
        zcdns-ssh-key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
        ```

2.  **Client-Side:** Initiate an SSH connection to the server, using your domain as the username. The `-L` flag forwards a local port to the desired destination on the server.

    ```bash
    ssh your-domain.com@your-server.com -p 2222 -L 443:localhost:443
    ```

3.  **Server-Side:** The Go application listens for SSH connections. When a connection is received, it:
    *   Parses the username to get the domain (`your-domain.com`).
    *   **Authorizes** the request by verifying that the domain's CNAME record points to the configured validation domain.
    *   **Authenticates** the user by looking up the `zcdns-ssh-key` TXT record and comparing it with the public key provided by the client.
    *   If both checks pass, the server establishes the tunnel, forwarding traffic as requested by the client's `-L` flag.

## Features

*   **Stateless and "DB-less":** No database or server-side state to manage. All configuration is in DNS.
*   **DNS-Based Authentication & Authorization:** Securely manage access and routing through your DNS provider.
*   **Simple Client-Side Setup:** Uses the standard `ssh` command.
*   **Flexible Port Forwarding:** The client determines the port forwarding rules.
*   **Scalable and Resilient:** The stateless nature of the server makes it easy to scale and deploy.

## Use Cases

*   **Exposing local development servers.**
*   **Custom domains for SaaS applications.**
*   **Running services on dynamic IP addresses.**
*   **Building decentralized and resilient systems.**