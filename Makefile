run: run.o scheme.o benchmark.o util.o ec-dsa.o ec-kcdsa.o
	gcc -g -o $@ $^ -lcrypto -lc

%.o: %.c
	gcc -g -c $^

clean:
	rm -rf *.o run

