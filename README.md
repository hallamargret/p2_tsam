# Project 2 in T-409-TSAM 

![RU Logo](https://www.ru.is/media/HR_logo_midjad_hires.jpg)

## Students:
### Eva Sol Petursdottir (evap19) 

### Halla Margret Jonsdottir (hallaj19)

### 28. september 2021

## Project 2 :: Ports!

## About the program

### What this program does and in what OS it was created/tested

#### Part 1

In this part of the project we have a program that is a UDP port scanner. It scans and prints all open ports between two port numbers that the program takes in as an argument. The program scans for the ports on the IP address that the program also takes in as an argument. 

#### Part 2

In this part there is another program, puzzlesolver, that solves the puzzle ports. It sends UDP messages to all the open ports and gets instructions back on how to reveal the two hidden ports and the secret phrase. The program can the IP address as an argument and it can also take the IP address and the 4 open ports. If the program only gets the IP address it calls the scanner from part 1 to get the open ports.

#### Part 3

In this part the program puzzlesolver was modefied to knock on the hidden ports in the order that the oracle port gives when receving the hidden ports. Each knock contains the secret phrase from part 2 as a messages.

This program was created on a MacBook Air (13-inch, Early 2015) with macOS Big Sur version 11.2.3, with a 1,6 GHz Dual-Core Intel Core i5 Processor and a MacBook Air (13-inch, Early 2014) with MacOS High Sierra version 10.13.6, with a 1,4 GHz Intel Core i5 processor. The program was written and tested in Visual Studio Code using the terminal and the terminal in VSCode.

*NOTE:* We could not finnish the evil-bit part so the second hidden port is hard-coded into the program

## What is needed to install if anything
The computer that the program is run on needs to have c++ installed and GNU to compile the c++ program.

## How to compile and run the programs using command line commands
You can compile the program by open the terminal, be located in the right directory, and type the command

```
make
```
because of the make file that is in this folder, both the programs will compile.

If you prefer to compile the programs by yourself, then you can compile the scanner program by typing this command:

```
g++ -std=c++11 scanner.cpp -o ./scanner
```
Compile the puzzlesolver program by typing this command:
```
g++ -std=c++11 puzzlesolver.cpp -o ./puzzlesolver
```
Or both at the same time by typing this command:
```
g++ -std=c++11 *.cpp -o ./puzzlesolver
```
The last one is the command used in the makefile
## Run the programs

### Part 1
After compilation, we can run the program on the terminal. 
```
 ./scanner <IP address> <low port> <high port>
```
where the IP address is the address you want to scan on and all the ports between "low port" and "high port" will be scaned, e.g. ./scanner 130.208.242.120 4000 4100 listens to IP 130.208.242.120 and ports from 4000 to 4100.

### Part 2 and 3
After compilation, we can run the program on the terminal. If we don't know tho open ports we can run it with the following command:
```
 ./puzzlesolver <IP address>
```
If we know the open ports we can run the program with the following command:

```
 ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>
```


