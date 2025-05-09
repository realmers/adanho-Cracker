# Password Cracker

This project contains multiple implementations of a program that attempts to crack passwords from a UNIX-style password file using a dictionary attack.

## Prerequisites

- Java Development Kit (JDK) installed (for `javac` and `java` commands).
- The `jcrypt.java` file must be in the same directory as the `PasswordCrack*.java` files or accessible in the classpath.

## Implementations

There are three implementations available:

1.  `PasswordCrack.java`: Breadth-first approach.
2.  `PasswordCrackDepthFirst.java`: Depth-first approach.
3.  `PasswordCrackMultiThread.java`: Multithreaded breadth-first approach.

## Compilation

To compile a specific program, navigate to the directory containing the Java files and run the corresponding command in your terminal. You always need to include `jcrypt.java` in the compilation.

### Compiling `PasswordCrack.java` (Breadth-First)

```bash
javac PasswordCrack.java jcrypt.java
```

### Compiling `PasswordCrackMultiThread.java` (Multithreaded Breadth-First)

```bash
javac PasswordCrackMultiThread.java jcrypt.java
```

This will generate the respective `.class` files (e.g., `PasswordCrack.class`, `PasswordCrackDepthFirst.class`, `PasswordCrackMultiThread.class`, and `jcrypt.class`).

## Running the Programs

After successful compilation, you can run the desired program using the following command format:

```bash
java <ProgramName> <dictionary_file_path> <password_file_path>
```

Replace `<ProgramName>` with the class name of the program you want to run (e.g., `PasswordCrack`, `PasswordCrackDepthFirst`, `PasswordCrackMultiThread`).
Replace `<dictionary_file_path>` with the path to your dictionary file (e.g., `dict.txt`).
Replace `<password_file_path>` with the path to the password file you want to crack (e.g., `passwd2.txt`).

### Example: Running `PasswordCrack.java`

If your dictionary is named `dict.txt` and your password file is `passwd2.txt`, and both are in the same directory as the compiled classes:

```bash
java PasswordCrack dict.txt passwd2.txt
```

### Example: Running `PasswordCrackDepthFirst.java`

```bash
java PasswordCrackDepthFirst dict.txt passwd2.txt
```

### Example: Running `PasswordCrackMultiThread.java`

```bash
java PasswordCrackMultiThread dict.txt passwd2.txt
```

The programs will print any cracked passwords to the standard output, one password per line. Error messages or warnings will be printed to standard error.
