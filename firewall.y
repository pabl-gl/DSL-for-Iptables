%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int yylex();
extern int yylineno;
extern FILE *yyin;

void yyerror(const char *s);

int error_count = 0;
int rule_error = 0;
char print_buf[4096] = ""; //Almacena el texto a imprimir de cada regla

void validate_ip(const char* ip){
    char buf[256];
    char *save, *token, *slash;
    int octet, count = 0;

    strcpy(buf, ip);
    slash = strchr(buf, '/');

    if (slash) {
        *slash = '\0';
        slash++;

        int mask = atoi(slash);
        if (mask < 0 || mask > 32) {
            fprintf(stderr,
                "Error: invalid subnet mask %d at line %d\n",mask, yylineno);
            error_count++;
            rule_error++;
        }
    }

    token = strtok_r(buf, ".", &save);

    while (token != NULL) {
        octet = atoi(token);

        if (octet < 0 || octet > 255) {
            fprintf(stderr,
                "Error: invalid octet %d in IP '%s' at line %d\n",
                count + 1, ip, yylineno);
            error_count++;
            rule_error++;

        }

        count++;
        token = strtok_r(NULL, ".", &save);
    }

    if (count != 4) {
        fprintf(stderr,
            "Error: Invalid IP address '%s' (wrong number of octets) at line %d\n",
            ip, yylineno);
        error_count++;
        rule_error++;
    }
}
void validate_port(unsigned int port) {
    if (port < 1 || port > 65535) {
        fprintf(stderr,
            "Error: Invalid port number %d (valid range: 1-65535) at line %d\n",
            port, yylineno);
        error_count++;
        rule_error++;
    }
}

void validate_port_range(int start, int end) {
    validate_port(start);
    validate_port(end);
    if (start > end) {
        fprintf(stderr, "Error: Invalid port range %d-%d at line %d\n", start, end, yylineno);
        error_count++;
        rule_error++;
    }
}

void validate_state(const char *state) {
    if (strcmp(state, "NEW") != 0 && strcmp(state, "ESTABLISHED") != 0 &&
        strcmp(state, "RELATED") != 0 && strcmp(state, "INVALID") != 0) {
        fprintf(stderr, "Error: Unrecognized connection state '%s' at line %d\n", state, yylineno);
        error_count++;
        rule_error++;
    }
}

void validate_proto_port(const char *proto) {
    if (proto && strcmp(proto, "icmp") == 0) {
        fprintf(stderr, "Error: Protocol ICMP is incompatible with port specification at line %d\n", yylineno);
        error_count++;
        rule_error++;
    }
}
void flush_buffer() {
    // Imprime la regla si no se cometieron errores y libera memoria para una siguiente regla
    if (!rule_error) {
        printf("%s", print_buf);
    }
    print_buf[0] = '\0';
    rule_error = 0;
}

%}

%union {
    int num;
    char *str;
}

%token ACCEPT DROP REJECT_ACTION FROM TO PROTO DPORT SPORT IF STATE DEFAULT ANY
%token COMMA DASH
%token <str> IDENTIFIER IP_ADDR
%token <num> NUMBER

%type <str> action source destination protocol_strict protocol_opt port_strict port_opt state_cond 
%start s

%%
s: program
    ;

program:
    | program rule
    ;


rule:
    action protocol_strict port_opt FROM source TO destination state_cond {
        /* Acción + Protocolo + Puerto (opc) + Origen + Destino + Estado */

        if ($3 != NULL) {
            validate_proto_port($2);
        }
        
        snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", "iptables -A INPUT");
        
        // Fuente: IP/Subnet (-s) vs Interfaz (-i)
        if (strcmp($5, "any") != 0 && strcmp($5, "all") != 0) {
            if (strchr($5, '.') != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -s %s", $5);
            else 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -i %s", $5);
        }
        // Destino: IP/Subnet (-d) vs Interfaz (-o)
        if (strcmp($7, "any") != 0 && strcmp($7, "all") != 0) {
            if (strchr($7, '.') != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -d %s", $7);
            else 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -o %s", $7);
        }
        
        // Añadir protocolo
        if ($2 != NULL) 
            snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -p %s", $2);
        
        // Añadir puertos
        if ($3 != NULL) 
            snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $3);        
        
        // Añadir estado
        if ($8 != NULL) 
            snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $8);        

        // Finalizar con acción (-j)
        snprintf(print_buf + strlen(print_buf), sizeof(print_buf) - strlen(print_buf), " -j %s\n",
            strcmp($1, "accept") == 0 ? "ACCEPT" :
            strcmp($1, "drop") == 0   ? "DROP" :
                                            "REJECT");
        flush_buffer();

        free($1); free($5); free($7);
        if ($2) free($2); if ($3) free($3); if ($8) free($8);
    }

    | action port_strict FROM source TO destination state_cond {
        /* Acción + Puerto estricto + Origen + Destino + Estado (Sin protocolo explícito) */
        
        snprintf(print_buf, sizeof(print_buf), "%s", "iptables -A INPUT");
        
        if (strcmp($4, "any") != 0 && strcmp($4, "all") != 0) {
            if (strchr($4, '.') != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -s %s", $4);
            else
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -i %s", $4);
        }

        if (strcmp($6, "any") != 0 && strcmp($6, "all") != 0) {
            if (strchr($6, '.') != NULL)
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -d %s", $6);
            else 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -o %s", $6);
        }

        if ($2 != NULL)
            snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $2);
        
        if ($7 != NULL) 
            snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $7);        

        snprintf(print_buf + strlen(print_buf), sizeof(print_buf) - strlen(print_buf), " -j %s\n",
            strcmp($1, "accept") == 0 ? "ACCEPT" :
            strcmp($1, "drop") == 0   ? "DROP" :
                                            "REJECT");
        flush_buffer();
        free($1); free($4); free($6);
        if ($2) free($2); if ($7) free($7);
    }

    | action FROM source TO destination protocol_opt port_opt state_cond {
        /* Acción + Origen + Destino + Opciones extra */
        if ($7 != NULL && $6 != NULL) {
            validate_proto_port($6);
        }
        if (strcmp($3, "default") == 0) {
            //Política por defecto
            snprintf(print_buf, sizeof(print_buf),
            "iptables -P INPUT %s\n",
            strcmp($1, "accept") == 0 ? "ACCEPT" : "DROP");

        } else {
            snprintf(print_buf, sizeof(print_buf), "%s", "iptables -A INPUT");
            
            if (strcmp($3, "any") != 0 && strcmp($3, "all") != 0) {
                if (strchr($3, '.') != NULL) 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -s %s", $3);
                else 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -i %s", $3);
                
            }
            
            if (strcmp($5, "any") != 0 && strcmp($5, "all") != 0) {
                if (strchr($5, '.') != NULL) 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -d %s", $5);
                
                else 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -o %s", $5);
            }
            
            if ($6 != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -p %s", $6);
            if ($7 != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $7);        
            
            if ($8 != NULL) 
                snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), "%s", $8);        

            snprintf(print_buf + strlen(print_buf), sizeof(print_buf) - strlen(print_buf), " -j %s\n",
                strcmp($1, "accept") == 0 ? "ACCEPT" :
                strcmp($1, "drop") == 0   ? "DROP" :
                                                "REJECT");
        }
        flush_buffer();
        free($1); free($3); free($5);
        if ($6) free($6); if ($7) free($7); if ($8) free($8);
    }

    | action FROM source {
        if (strcmp($3, "default") == 0) {
            snprintf(print_buf, sizeof(print_buf),
                "iptables -P INPUT %s\n",
                strcmp($1, "accept") == 0 ? "ACCEPT" : "DROP");

        } else {
            snprintf(print_buf, sizeof(print_buf), "%s", "iptables -A INPUT");
    
            if (strcmp($3, "any") != 0 && strcmp($3, "all") != 0) {
                if (strchr($3, '.') != NULL) 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -s %s", $3);
                else 
                    snprintf(print_buf + strlen(print_buf),  sizeof(print_buf) - strlen(print_buf), " -i %s", $3);
            }
            snprintf(print_buf + strlen(print_buf), sizeof(print_buf) - strlen(print_buf), " -j %s\n",
                strcmp($1, "accept") == 0 ? "ACCEPT" :
                strcmp($1, "drop") == 0   ? "DROP" :
                                                "REJECT");
        }
        flush_buffer();
        free($1); free($3);
    }
    ;

action:
    ACCEPT { $$ = strdup("accept"); }
    | DROP { $$ = strdup("drop"); }
    | REJECT_ACTION { $$ = strdup("reject"); }
    ;

source:
    IP_ADDR {
        validate_ip($1);     
        $$ = $1;
    }
    | IDENTIFIER { $$ = $1; }
    | ANY { $$ = strdup("any"); }
    | DEFAULT { $$ = strdup("default"); }
    ;

destination:
    IP_ADDR {
        validate_ip($1);     
        $$ = $1;
    }
    | IDENTIFIER { $$ = $1; }
    | ANY { $$ = strdup("any"); }
    ;

protocol_strict: 
    PROTO IDENTIFIER { $$ = $2; }
    ;

protocol_opt: 
        { $$ = NULL; }
    | protocol_strict { $$ = $1; }
    ;

port_strict:
      DPORT NUMBER { 
        validate_port($2);
        char buf[128];
        sprintf(buf, " --dport %d", $2);
        $$ = strdup(buf);
    }
    | DPORT NUMBER DASH NUMBER {
        validate_port_range($2, $4);
        char buf[128];
        sprintf(buf, " --dport %d:%d", $2, $4);
        $$ = strdup(buf);
    }
    | DPORT NUMBER COMMA NUMBER {
        validate_port($2);
        validate_port($4);
        char buf[128];
        sprintf(buf, " -m multiport --dports %d,%d", $2, $4);
        $$ = strdup(buf);
    }
    | SPORT NUMBER {
        validate_port($2);
        char buf[128];
        sprintf(buf, " --sport %d", $2);
        $$ = strdup(buf);
    }
    ;

port_opt: 
     { $$ = NULL; }
    | port_strict  { $$ = $1; }
    ;

state_cond: { $$ = NULL; }
    | IF STATE IDENTIFIER {
        validate_state($3);
        char buf[128];
        sprintf(buf, " -m state --state %s", $3);
        $$ = strdup(buf);
        free($3);
    }
    ;

%%

void yyerror(const char *s) {
    fprintf(stderr, "Parse error: %s at line %d\n", s, yylineno);
    error_count++;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        yyin = fopen(argv[1], "r");
        if (!yyin) {
            perror("Error opening file");
            return 1;
        }
    }
    
    yyparse();
    
    if (argc > 1) {
        fclose(yyin);
    }
    
    if (error_count > 0) {
        fprintf(stderr, "\nCompilation completed with %d error(s)\n", error_count);
        return 1;
    }
    
    return 0;
}
