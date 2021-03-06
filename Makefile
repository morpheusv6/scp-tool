# 
# Makefile for SCP tool
#

TARGETS : ncsuenc ncsudec

all : $(TARGETS) 

serializer.o : serializer.c serializer.h
	@$(CC) -c $(CFLAGS) serializer.c -o $@

utilities.o : utilities.c utilities.h
	@$(CC) -c $(CFLAGS) utilities.c -o $@

scp.o : scp.c utilities.h scp.h
	@$(CC) -c $(CFLAGS) scp.c -o $@

ncsuenc.o : ncsuenc.c utilities.h scp.h 
	@$(CC) -c $(CFLAGS) ncsuenc.c -o $@

ncsudec.o : ncsudec.c utilities.h scp.h
	@$(CC) -c $(CFLAGS) ncsudec.c -o $@

ncsuenc : serializer.o utilities.o scp.o ncsuenc.o 
	@$(CC) $(CFLAGS) -o $@ serializer.o utilities.o scp.o ncsuenc.o -lgcrypt

ncsudec : serializer.o utilities.o scp.o ncsudec.o 
	@$(CC) $(CFLAGS) -o $@ serializer.o utilities.o scp.o ncsudec.o -lgcrypt

clean : 
	$(RM) *.out *.o *~ *.bak *.ncsu ncsuenc ncsudec $(TARGETS)
	@echo Clean complete.
