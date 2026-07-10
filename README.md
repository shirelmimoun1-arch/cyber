# Cybersecurity Projects

A collection of hands-on cybersecurity projects completed as part of an academic cybersecurity course.  
The projects focus on vulnerability analysis, network protocols, web security, memory exploitation, and low-level programming in controlled lab environments.

> **Ethical Use Notice**  
> These projects were developed and tested only in isolated academic environments created specifically for security education.  
> The code is intended for learning, research, and defensive security purposes only.

---

## Projects Overview

| Project | Main Topics | Technologies |
|---|---|---|
| [Buffer Overflow Exploitation](#1-buffer-overflow-exploitation) | Stack corruption, return-address overwrite, shellcode | C, x86-64, TCP sockets |
| [Kaminsky DNS Cache Poisoning](#2-kaminsky-dns-cache-poisoning) | DNS spoofing, packet crafting, cache poisoning | C, LDNS, libpcap, Wireshark |
| [Cross-Site Scripting Attacks](#3-cross-site-scripting-attacks) | Reflected, Stored, and DOM-based XSS | C, JavaScript, HTTP, MariaDB |
| [HTTP Response Splitting and Blind SQL Injection](#4-http-response-splitting-and-blind-sql-injection) | Cache poisoning, HTTP parsing, data extraction | C, TCP sockets, SQL, Wireshark |

---

## 1. Buffer Overflow Exploitation

### Overview

This project demonstrates how a stack-based buffer overflow can alter a program's control flow.

The exploit constructs a custom payload that overwrites the vulnerable function's saved return address and redirects execution to machine code placed inside the supplied buffer.

### Implementation

The exploit:

- Receives the target stack address and return-address offset at runtime.
- Allocates a dynamically sized payload buffer.
- Inserts x86-64 machine code that performs an `execve` system call.
- Stores the required command path and argument array inside the payload.
- Calculates their runtime addresses relative to the leaked stack address.
- Replaces placeholder values in the machine code with the calculated addresses.
- Overwrites the saved return address with the address of the injected code.
- Sends the completed payload to the vulnerable service through a TCP connection.

### Key Concepts

- Stack memory layout
- Saved return-address overwrite
- Runtime address calculation
- Shellcode construction
- x86-64 calling conventions
- `execve` system call
- TCP socket programming

### Main File

```text
buffer_overflow_attack.c
```

---

## 2. Kaminsky DNS Cache Poisoning

### Overview

This project reconstructs a Kaminsky-style DNS cache-poisoning attack against a vulnerable DNS resolver in an isolated network.

The objective is to make the resolver cache a forged DNS record that maps a target domain to an attacker-controlled IP address.

### Architecture

The implementation contains two cooperating components:

#### Attacker Authoritative Name Server

The attacker's DNS server:

- Receives resolver queries for an attacker-controlled domain.
- Identifies the UDP source port used by the resolver.
- Returns a valid DNS response for the attacker-controlled domain.
- Sends the discovered resolver port to the attacker client through a TCP control channel.

#### Attacker Client

The client:

- Triggers DNS lookups for newly generated subdomains.
- Uses the resolver port learned from the attacker-controlled name server.
- Creates forged DNS responses with guessed transaction IDs.
- Crafts Ethernet, IPv4, UDP, and DNS headers.
- Inserts a malicious DNS record into the forged response.
- Sends many spoofed responses during the resolver's query window.

### Packet Analysis

Wireshark was used to:

- Inspect DNS requests and responses.
- Measure the approximate resolver-to-authoritative-server round-trip time.
- Analyze DNS transaction IDs, source ports, flags, and resource records.
- Debug packet construction and attack timing.

### Key Concepts

- DNS resolution and caching
- Kaminsky attack
- Transaction-ID guessing
- UDP source-port discovery
- DNS resource records
- Raw packet construction
- IP and UDP checksums
- Packet injection with `libpcap`
- DNS packet creation with `LDNS`

### Main Files

```text
DNS Cache Poisoning_server.c
DNS Cache Poisoning_client.c
```

---

## 3. Cross-Site Scripting Attacks

### Overview

This project explores three major forms of Cross-Site Scripting:

1. Reflected XSS
2. Stored XSS
3. DOM-based XSS

Each attack was implemented in a controlled environment to demonstrate how unsafe handling of user-controlled input can lead to client-side code execution and session compromise.

### Reflected XSS

A malicious JavaScript payload is inserted into a vulnerable URL parameter.  
The server reflects the unsanitized input into the generated HTML response, causing the payload to execute when the victim opens the crafted URL.

The payload sends the victim's session cookie to an attacker-controlled TCP server. The captured cookie is then used to request a protected page.

### Stored XSS

A malicious payload is submitted through an HTTP `POST` request and stored in the application's database.

When an authenticated user later opens the page that displays the stored content, the payload executes in that user's browser and sends the session cookie to the attacker-controlled server.

### DOM-Based XSS

A malicious payload is placed in the URL fragment.

Client-side JavaScript reads the fragment and inserts it into the DOM without sufficient sanitization. Since URL fragments are handled in the browser, the vulnerable server does not need to process the payload.

### Attacker Server

The attacker component is implemented as a minimal TCP/HTTP server that:

- Listens for HTTP requests generated by the injected JavaScript.
- Extracts the session cookie from the request.
- Returns a minimal valid HTTP response.
- Uses the captured cookie in a new HTTP request.
- Saves the protected server response to a local file.

### Key Concepts

- Reflected XSS
- Stored XSS
- DOM-based XSS
- Unsafe DOM manipulation
- JavaScript payload execution
- Session cookies
- Session hijacking
- HTTP `GET` and `POST`
- URL encoding
- TCP server implementation
- Database-backed web applications

### Main Files

```text
XSS_reflected.c
XSS_stored.c
XSS_dom.c
ex3_db_insert_stored.c
url_reflected.txt
url_dom.txt
```

---

## 4. HTTP Response Splitting and Blind SQL Injection

This section contains two web-security exercises that focus on HTTP message parsing and database information leakage.

---

### 4.1 HTTP Response Splitting

#### Overview

The vulnerable application inserts user-controlled input directly into an HTTP response header without proper sanitization.

By injecting encoded carriage-return and line-feed characters, the payload terminates the original response and introduces a second forged HTTP response.

The forged response is interpreted by a vulnerable reverse proxy and stored in its cache, causing future requests for the target page to receive attacker-controlled content.

#### Implementation

The attack:

- Identifies a vulnerable URL parameter.
- Injects URL-encoded `CRLF` sequences.
- Terminates the original response body using chunked transfer encoding.
- Constructs a second valid HTTP response.
- Includes cache-related headers and controlled HTML content.
- Sends the malicious request and target-page request over the required TCP flow.
- Uses Wireshark to verify message boundaries and proxy behavior.

#### Key Concepts

- HTTP request and response structure
- CRLF injection
- HTTP response splitting
- Reverse-proxy behavior
- Web cache poisoning
- `Transfer-Encoding: chunked`
- Persistent TCP connections
- HTTP header analysis

#### Main File

```text
ex4_splitting.c
```

---

### 4.2 Boolean-Based Blind SQL Injection

#### Overview

This project implements an automated Boolean-based blind SQL injection tool.

The vulnerable web application does not directly reveal query results. Instead, it returns one of two different responses depending on whether the injected SQL condition evaluates to true or false.

The program uses this one-bit information channel to reconstruct database metadata and extract a target value.

#### Implementation

The tool:

- Injects SQL expressions through a vulnerable HTTP parameter.
- Distinguishes true and false conditions by parsing the HTTP response.
- Searches the database metadata tables to discover:
  - The target table name
  - The identifier column name
  - The password column name
- Extracts values one character at a time with `ASCII` and `SUBSTR`.
- Uses binary search over printable ASCII values to reduce the number of requests.
- Writes the recovered value to an output file.

### Why Binary Search?

Testing every printable character sequentially would require many HTTP requests per position.

Binary search reduces the number of guesses from approximately:

```text
O(n)
```

to:

```text
O(log n)
```

for each extracted character.

### Key Concepts

- SQL injection
- Boolean-based blind extraction
- `UNION SELECT`
- Database schema discovery
- `information_schema`
- `ASCII` and `SUBSTR`
- Binary search
- HTTP response parsing
- Automated data extraction

### Main File

```text
ex4_sqli.c
```

---

## Technologies and Tools

- **Languages:** C, JavaScript, SQL
- **Networking:** TCP, UDP, HTTP, DNS
- **Security Tools:** Wireshark
- **Libraries:** LDNS, libpcap
- **Environment:** Linux, Docker, isolated virtual networks
- **Database:** MariaDB
- **Concepts:** Web exploitation, packet analysis, memory corruption, raw packet crafting

---

## Skills Demonstrated

- Tracing execution flow through C programs
- Analyzing application and network behavior
- Constructing and parsing HTTP messages
- Inspecting DNS and HTTP traffic with Wireshark
- Developing client-server applications with sockets
- Crafting packets across multiple protocol layers
- Understanding memory layout and low-level execution
- Automating vulnerability exploitation in controlled environments
- Debugging complex security scenarios incrementally

---

## Repository Structure

A recommended repository layout is:

```text
cybersecurity-projects/
├── README.md
├── buffer-overflow/
│   ├── buffer_overflow_attack.c
│   └── explanation.md
├── dns-cache-poisoning/
│   ├── dns_cache_poisoning_server.c
│   ├── dns_cache_poisoning_client.c
│   └── explanation.md
├── xss-attacks/
│   ├── xss_reflected.c
│   ├── xss_stored.c
│   ├── xss_dom.c
│   ├── stored_payload_sender.c
│   └── explanation.md
└── web-attacks/
    ├── http_response_splitting.c
    ├── blind_sqli.c
    └── explanation.md
```

---

## Important Security Note

The source files may contain addresses, ports, payloads, or identifiers that were specific to the original academic lab.

Before publishing the repository, replace personal identifiers and lab-specific values with neutral placeholders, for example:

```c
#define TARGET_IP "LAB_TARGET_IP"
#define ATTACKER_IP "LAB_ATTACKER_IP"
#define STUDENT_ID "REDACTED"
```

Do not test these techniques against systems without explicit authorization.

---

## Author

**Shirel Mimoun**  
B.Sc. Electrical Engineering and Computer Science  
The Hebrew University of Jerusalem
