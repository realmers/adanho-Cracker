# Password Cracker

This program attempts to crack passwords from a UNIX-style password file using a dictionary attack.

## Prerequisites

- Java Development Kit (JDK) installed (for `javac` and `java` commands).
- The `jcrypt.java` file must be in the same directory as `PasswordCrack.java` or accessible in the classpath.

## Compilation

To compile the program, navigate to the directory containing `PasswordCrack.java` and `jcrypt.java` and run the following command in your terminal:

```bash
javac PasswordCrack.java jcrypt.java
```

This will generate `PasswordCrack.class` and `jcrypt.class` files.

## Running the Program

After successful compilation, you can run the program using the following command format:

```bash
java PasswordCrack <dictionary_file_path> <password_file_path>
```

Replace `<dictionary_file_path>` with the path to your dictionary file (e.g., `dict.txt`) and `<password_file_path>` with the path to the password file you want to crack (e.g., `passwd2.txt`).

### Example

If your dictionary is named `dict.txt` and your password file is `passwd2.txt`, and both are in the same directory as the compiled classes, you would run:

```bash
java PasswordCrack dict.txt passwd2.txt
```

The program will print any cracked passwords to the standard output, one password per line. Error messages or warnings will be printed to standard error.
