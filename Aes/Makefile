main: main.o AesAPI.o
	g++ main.o AesAPI.o -o main
main.o: main.cpp
	g++ -c main.cpp -o main.o
AesAPI.o: AesAPI.cpp
	g++ -c AesAPI.cpp -o AesAPI.o

clean:
	rm main main.o AesAPI.o
