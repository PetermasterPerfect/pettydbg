grammar commands;

command:  command0Arg | command1Arg | command2Arg;

command0Arg: CONTINUE 
	| RESTART 
	| THREADINFO 
	| MEMINFO 
	| NEXT 
	| STEPINTO 
	| FINISH 
	| REGISTERS 
	| BPOINTINFO ;

command1Arg: STACK (INT | HEXINT) 
	| DELBPOINT (INT | HEXINT) 
	| BPOINT (INT | HEXINT);

command2Arg: DISASSEMBLY (INT | HEXINT) (INT | HEXINT) ;


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