all: sandbox tracer tracee

sandbox: sandbox.o
	gcc -g sandbox.o -o sandbox

tracer: tracer.o
	gcc -g tracer.o -o tracer

tracee: tracee.o
	gcc -g tracee.o -o tracee

sandbox.o: sandbox.c
	gcc -g -c sandbox.c

tracer.o: tracer.c
	gcc -g -c tracer.c

tracee.o: tracee.c
	gcc -g -c tracee.c

clean:
	rm -f *.o sandbox tracer tracee
