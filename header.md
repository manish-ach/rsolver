## How a DNS message is structured

DNS messages are compact binary packets — not text.
They follow a **fixed format**, divided into **sections**:

```
+---------------------+
| Header              | (12 bytes)
+---------------------+
| Question            | (variable length)
+---------------------+
| Answer              | (variable length)
+---------------------+
| Authority           | (variable length)
+---------------------+
| Additional          | (variable length)
+---------------------+
```

Let’s break each down.

---

## 1️⃣ Header (12 bytes total)

Every DNS packet starts with a 12-byte header.

| Field   | Size    | Description                                                             |
| ------- | ------- | ----------------------------------------------------------------------- |
| ID      | 2 bytes | Random identifier to match query ↔ response                             |
| Flags   | 2 bytes | Contains bits like QR (query/response), opcode, recursion desired, etc. |
| QDCOUNT | 2 bytes | Number of questions                                                     |
| ANCOUNT | 2 bytes | Number of answers                                                       |
| NSCOUNT | 2 bytes | Number of authority records                                             |
| ARCOUNT | 2 bytes | Number of additional records                                            |

Example (hex view of a query header):

```
ab cd 01 00 00 01 00 00 00 00 00 00
```

→ ID = 0xabcd, QDCOUNT = 1 (one question)

---

## 2️⃣ Question section

Immediately after the 12-byte header comes the **Question** section.

It looks like this:

```
QNAME | QTYPE | QCLASS
```

### QNAME (domain name)

This is not plain text — it’s encoded as **length-prefixed labels**:

Example: `www.example.com`

Encoded as:

```
03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

Explanation:

* `03` = length of “www”
* `77 77 77` = ASCII “www”
* `07` = length of “example”
* `65 78 61 6d 70 6c 65` = “example”
* `03` = length of “com”
* `63 6f 6d` = “com”
* `00` = end of domain name

### QTYPE

2 bytes: the record type (e.g. `A`, `AAAA`, `MX`, etc.)

* `A` = 1
* `AAAA` = 28
* `MX` = 15

### QCLASS

2 bytes: usually 1 (meaning “IN” = Internet class)

So, a simple question looks like:

| Field  | Example (hex)                                      |
| ------ | -------------------------------------------------- |
| QNAME  | 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 |
| QTYPE  | 00 01                                              |
| QCLASS | 00 01                                              |

---

## 3️⃣ Answer / Authority / Additional

Each record has this general structure:

```
NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA
```

For example, an `A` record:

```
NAME: 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
TYPE: 00 01 (A)
CLASS: 00 01 (IN)
TTL: 00 00 00 3C (60 seconds)
RDLENGTH: 00 04
RDATA: C0 A8 01 01 (192.168.1.1)
```

---

## 🧩 Summary — A DNS Query Example

| Section  | Example (hex summary)                                            | Meaning                             |
| -------- | ---------------------------------------------------------------- | ----------------------------------- |
| Header   | `12 34 01 00 00 01 00 00 00 00 00 00`                            | ID=0x1234, 1 question               |
| Question | `03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01` | `www.example.com`, type A, class IN |

---

## Our goal

1. Parse the **header**.
2. Extract the **domain name** (QNAME).
3. Display the requested domain, record type, etc.

That way, when we run:

```bash
dig @127.0.0.1 -p 5353 example.com
```

our resolver will print:

```
Query ID: 0x1234
Questions: 1
Domain: example.com
Type: A
Class: IN
```

---
