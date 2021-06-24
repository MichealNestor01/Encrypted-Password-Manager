# Encrypted-Password-Manager
This is a simple command line based program which I created to learn about encryption and secure password protection.
Skills I learned creating this: 
- Hashing
- Encryption
- Python callback functions (threading Timer objects)
It uses a master password which secures the entire project.
A hashed version of the master password is all that is saved locally, and is used to verify logging in. 
And when a user logs in an encryption key is created with the plain text master password and this is used to encrypt all of the passwords, since the key is never saved locally, all passwords are secure. I also build in a timeout function, which forces the user to log back in after an amount of time has passed (this time is adjustable within the program)

