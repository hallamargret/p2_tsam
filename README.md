# Project 2 in T-409-TSAM Eva Sol Petursdottir (evap19) and Halla Margret Jonsdottir (hallaj19)

# p2_tsam

## About the program

### What this program does and in what OS it was created/tested



This program was created on a MacBook Air (13-inch, Early 2015) and a MacBook Air (13-inch, Early 2014!!!!!!!!! ath), macOS Big Sur version 11.2.3, with a 1,6 GHz Dual-Core Intel Core i5 Processor. The program was written and tested in Visual Studio Code using the terminal and the terminal in VSCode.


## What is needed to install if anything
The computer that the program is run on needs to have c++ installed and GNU to compile the c++ program.
It is recommended to have Visual Studio Code installed and run it in the terminal.


## How to compile and run the programs using command line commands
You can compile the client and the server programs by open the terminal (console line) and type the command

```
make
```
because of the make file that is in this folder, scanner.cpp will compile.

If you prefer to compile the programs by yourself, then you can compile the scanner program by typing this command

```
g++ -std=c++11 scanner.cpp -o scanner
```


After compilation, we must run the program on the terminal. 
```
 ./scanner <IP address> <low port> <high port>
```
where the "PORT" part is the number of the port you want the server to listen to, e.g. ./scanner 130.208.242.120 4018 4050 listens to skel from ports 4018 to 4050.



Thank you for your time and I hope you have a good day and enjoy this simple network program.
