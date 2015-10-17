all: sandbox tracer tracee

sandbox: sandbox.o
	gcc sandbox.o -o sandbox

tracer: tracer.o
	gcc tracer.o -o tracer

tracee: tracee.o
	gcc tracee.o -o tracee

sandbox.o: sandbox.c
	gcc -c sandbox.c

tracer.o: tracer.c
	gcc -c tracer.c

tracee.o: tracee.c
	gcc -c tracee.c

clean:
	rm -f *.o sandbox tracer tracee
