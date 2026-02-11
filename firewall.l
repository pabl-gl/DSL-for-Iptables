%{
#include <stdio.h>
#include <string.h>
#include "firewall.tab.h"
%}

%option noyywrap
%option yylineno

%%

"allow"         { return ACCEPT; }
"accept"        { return ACCEPT; }
"block"         { return DROP; }
"drop"          { return DROP; }
"deny"          { return DROP; }
"reject"        { return REJECT_ACTION; }
"from"          { return FROM; }
"to"            { return TO; }
"on"            { return TO; }
"protocol"      { return PROTO; }
"proto"         { return PROTO; }
"port"          { return DPORT; }
"dport"         { return DPORT; }
"sport"         { return SPORT; }
"if"            { return IF; }
"when"          { return IF; }
"state"         { return STATE; }
"default"       { return DEFAULT; }
"any"           { return ANY; }
"all"           { return ANY; }

[a-zA-Z_][a-zA-Z0-9_]*  { yylval.str = strdup(yytext); return IDENTIFIER; }


[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)? { yylval.str = strdup(yytext); return IP_ADDR; }

[0-9]+          { yylval.num = atoi(yytext); return NUMBER; }

":"             { return DASH; }
"-"             { return DASH; }
","             { return COMMA; }
";"             {}

[ \t\r\n]+      {}

"#"[^\n]*       {}
"//"[^\n]*      {}

.               { fprintf(stderr, "Error: Invalid character '%s' at line %d\n", yytext, yylineno); }

%%
