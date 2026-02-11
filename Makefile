FUENTE = firewall
ENTRADA = test.txt
SALIDA = firewall.sh
LIB = -lfl

all: $(FUENTE)

# BISON
firewall.tab.c firewall.tab.h: firewall.y
	bison -d firewall.y

# FLEX
lex.yy.c: firewall.l firewall.tab.h
	flex firewall.l

# COMPILACIÓN
$(FUENTE): lex.yy.c firewall.tab.c
	gcc  -o $(FUENTE) lex.yy.c firewall.tab.c $(LIB)

# EJECUCIÓN: lee test.txt y produce salida.sh
run: $(FUENTE)
	./$(FUENTE) < $(ENTRADA) > $(SALIDA)
	chmod +x $(SALIDA)
	@echo "Salida generada en $(SALIDA)"

clean:
	rm -f $(FUENTE) lex.yy.c firewall.tab.c firewall.tab.h $(SALIDA)

.PHONY: all clean run
