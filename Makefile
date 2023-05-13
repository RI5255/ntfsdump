ntfsdump : ntfsdump.c 
	gcc -Wall -o $@ $^

clean:
	rm -f ntfsdump

.PHONY: clean