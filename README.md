This project implements a secure file storage and user authentication system designed to provide robust data protection and access control. The system leverages modern encryption techniques, including RSA (asymmetric encryption), AES (symmetric encryption), HMAC (message authentication codes), and digital signatures to secure both user data and file content.

To get started with this project, clone the repository and set up the necessary environment:
git clone https://github.com/yourusername/secure-file-storage.git
cd secure-file-storage

Prerequesites: 
- The project is built using Go. Ensure that you have Go installed on your system.
- Dependencies: The project requires several dependencies. To install them, run:
  go mod tidy
This will start the server, and you can interact with the authentication and file storage system.

Key Features: 

User Authentication: 

  1. Account Setup:
  On user registration, key pairs for digital signatures and RSA encryption are   generated. The root key is derived   from the password using Argon2 and is used   to derive encryption and MAC keys.
  
    2. Logging In:
    During login, the root key is re-derived from the password, and the user data   is decrypted and verified using      HMAC.

File Storage: 
  1. Storing Files:
  Files are encrypted with a file key and stored as FileNode and ContentNode      structs. A linked list of content nodes is maintained for large files.
  
  2. Appending to Files:
  New content can be appended to existing files by creating new ContentNode       structs and updating the FileHead    linked list.

File Sharing: 

  1. Invitations:
  Users can share files by creating invitations encrypted with the recipient's    public key. The invitations are      signed with the sender's private key.

  2. Revoking Access:
  To revoke access, the file key is updated, and the revoked user is removed      from the file's access list.

Helper Methods
- getUUID(query, username): Derives a UUID based on the given query and username.
- symEncThenTag(encKey, macKey, content, id): Encrypts and tags the content using symmetric encryption.
- symVerifyThenDec(encKey, macKey, id): Verifies and decrypts content using symmetric encryption.
- asymEncThenTag(username, signKey, content, id): Encrypts and tags content using asymmetric encryption.
- asymVerifyThenDec(username, decKey, id): Verifies and decrypts content using asymmetric encryption.

Security Considerations: 
- Argon2 is used for password hashing and key derivation to ensure resistance against brute-force attacks.
- RSA encryption (PKE) and digital signatures (DS) ensure that user keys are securely managed and verified.
- HMAC is used to verify the integrity of data, ensuring that data has not been tampered with.
- AES encryption is used to securely encrypt files and user data.

Contributers: 
This project was built by Phoebe Troup-Galligan and Keaton Elvis. 

