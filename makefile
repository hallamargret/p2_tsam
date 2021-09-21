default: compile

compile:
	g++ -std=c++11 scanner.cpp -o scanner
	g++ -std=c++11 puzzlesolver.cpp -o puzzlesolver

