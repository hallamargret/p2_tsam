# Project 2 in T-409-TSAM 

![RU Logo](https://www.ru.is/media/HR_logo_midjad_hires.jpg)

## Students:
### Eva Sol Petursdottir (evap19) 

### Halla Margret Jonsdottir (hallaj19)

## Project 2 :: Ports! - Part 1

## About the program

### What this program does and in what OS it was created/tested

This program is a UDP port scanner which scans and prints all open ports between two port numbers that the program takes in as an argument. The program scans for the ports on the IP address that the program also takes in as an argument. 


This program was created on a MacBook Air (13-inch, Early 2015) with macOS Big Sur version 11.2.3, with a 1,6 GHz Dual-Core Intel Core i5 Processor and a MacBook Air (13-inch, Early 2014) with MacOS High Sierra version 10.13.6, with a 1,4 GHz Intel Core i5 processor. The program was written and tested in Visual Studio Code using the terminal and the terminal in VSCode.


## What is needed to install if anything
The computer that the program is run on needs to have c++ installed and GNU to compile the c++ program.

## How to compile and run the programs using command line commands
You can compile the program by open the terminal, be located in the right directory, and type the command

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

where the "IP address" is the address you want to scan on and all the ports between "low port" and "high port" will be scaned, e.g. ./scanner 130.208.242.120 4000 4100 listens to IP 130.208.242.120 and ports from 4000 to 4100.


Thank you for your time and I hope you have a good day and enjoy this simple scanner program.
