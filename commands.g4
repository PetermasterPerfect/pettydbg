grammar commands;

command:  command0arg | command1arg | command2arg;

command0arg: CONTINUE NEWLINE
	| RESTART NEWLINE
	| THREADINFO NEWLINE
	| MEMINFO NEWLINE
	| NEXT NEWLINE
	| STEPINTO NEWLINE
	| FINISH NEWLINE
	| REGISTERS NEWLINE
	| BPOINTINFO NEWLINE;

command1arg: STACK (INT | HEXINT) NEWLINE
	| DELBPOINT (INT | HEXINT) NEWLINE
	| BPOINT (INT | HEXINT);

command2arg: DISASSEMBLY (INT | HEXINT) (INT | HEXINT) NEWLINE;


INT: [0-9]+;
HEXINT: '0x' [0-9a-fA-F]+;

CONTINUE: 'c';
RESTART: 'r';
THREADINFO: 'thinfo';
MEMINFO: 'meminfo';
NEXT: 'n';
STEPINTO: 's';
FINISH: 'f';
REGISTERS: 'reg';
STACK: 'stack';
BPOINT: 'bp';
DELBPOINT: 'delbp';
BPOINTINFO: 'bpinfo';
DISASSEMBLY: 'dis';
NEWLINE: '\r'? '\n';
WS : [ \t]+ -> skip ;